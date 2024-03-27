package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/mjl-/bstore"
)

type ops struct {
	URL string
	Key string
}

// We use an HTTP connection pool with short-lived connections: We periodically
// request a /latest, then fetch a few tiles. No need to keep those connections
// alive for long.
var httpClient = newHTTPClient()

func newHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.IdleConnTimeout = 10 * time.Second
	return &http.Client{
		Transport: transport,
	}
}

func (o ops) ReadRemote(path string) (rbuf []byte, rerr error) {
	slog.Info("ReadRemote", "path", path)
	defer func() {
		var more string
		if strings.HasPrefix(path, "/tile/") {
			more = fmt.Sprintf("%d bytes", len(rbuf))
		} else {
			more = fmt.Sprintf("data %q", rbuf)
		}
		slog.Info("ReadRemote done", "path", path, "done", more, "err", rerr)
	}()

	for !ratelimitSumdb.Add(net.IPv6zero, time.Now(), 1) {
		slog.Info("waiting for doing another outgoing sumdb request")
		time.Sleep(time.Second)
	}

	metricSumdbRequests.Inc()

	resp, err := httpClient.Get(o.URL + path)
	if err != nil {
		return nil, fmt.Errorf("http get from sumdb: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http get from sumdb not 200 ok, but %s", resp.Status)
	}
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %v", err)
	}
	return buf, nil
}

func (o ops) ReadCache(file string) (rbuf []byte, rerr error) {
	slog.Info("ReadCache", "file", file)
	defer func() {
		slog.Info("ReadCache done", "file", file, "bytes", len(rbuf), "err", rerr)
	}()

	p := filepath.Join("data/cache", file)
	return os.ReadFile(p)
}

func (o ops) WriteCache(file string, data []byte) {
	slog.Info("WriteCache", "file", file, "bytes", len(data))

	p := filepath.Join("data/cache", file)
	os.MkdirAll(filepath.Dir(p), 0700)
	err := os.WriteFile(p, data, 0600)
	if err != nil {
		err := os.Remove(p)
		logCheck(err, "remove after failed write")
	}
}

func (o ops) Log(msg string) {
	slog.Warn("tlogclient log", "msg", msg)
}

func (o ops) SecurityError(msg string) {
	metricTlogSecurityErrors.Inc()
	slog.Error("tlog security error", "err", msg)
}

func initTlogTest() {
	err := database.Write(context.Background(), func(tx *bstore.Tx) error {
		ts := TreeState{ID: 1}
		if err := tx.Get(&ts); !resetTree && err == nil && !ts.Test {
			slog.Error("refusing to start in test mode on non-test tree state in database")
			os.Exit(1)
		}

		tx.Delete(&TreeState{ID: 1}) // Ignore error.

		ts = TreeState{ID: 1, RecordsInitial: testLatestRecords0, RecordsProcessed: testLatestRecords0}
		if err := tx.Insert(&ts); err != nil {
			return fmt.Errorf("insert initial treestate: %v", err)
		}

		return nil
	})
	if err != nil {
		logFatalx("init tlog for test", err)
	}
	slog.Info("initialized tlog for testing")
}

func openTlog() {
	ts := TreeState{ID: 1}
	if err := database.Get(context.Background(), &ts); err != nil && err != bstore.ErrAbsent {
		logFatalx("get initial treestate", err)
	} else if resetTree || err == bstore.ErrAbsent {
		delay := time.Second
		for {
			if delay > time.Second {
				slog.Info("will retry initializing transparency log state", "delay", delay)
			}
			time.Sleep(delay)
			delay *= 2

			slog.Info("fetching transparency log position for initial state")
			latestBuf, err := tlogclient.ops.ReadRemote("/latest")
			if err != nil {
				logErrorx("reading initial transparency log latest position", err)
				continue
			}

			ntree, _, err := tlogclient.forward(latestBuf)
			if err != nil {
				logErrorx("forwarding to initial latest position", err)
				continue
			}

			// Start processing a bit before the end, so we immediately fetch some packages.
			n := ntree.N - 1000
			if n < 0 {
				n = 0
			}

			ts = TreeState{ID: 1, RecordsInitial: n, RecordsProcessed: n}
			err = database.Write(context.Background(), func(tx *bstore.Tx) error {
				if resetTree {
					// Not checking error. We'll get it on insert.
					tx.Delete(&TreeState{ID: 1})
				}
				return tx.Insert(&ts)
			})
			if err != nil {
				logFatalx("storing initial transparency log position", err)
			}
			slog.Info("initialized transparency log", "position", ntree.N)
			break
		}
	} else if ts.Test {
		logFatalx("refusing to start in non-test mode on test tree state in database", nil)
	} else {
		slog.Info("starting with transparency log from database", "position", ts.RecordsProcessed)
	}

	metricTlogRecords.Set(float64(ts.RecordsProcessed))

	slog.Info("will follow transparency log with periodic fetches of /latest")
	watchTlog()
}

func watchTlog() {
	for {
		err := stepTlog()
		if err != nil {
			logErrorx("moving tlog forward", err)
		}
		time.Sleep(config.SumDB.QueryLatestInterval)
	}
}

func stepTlog() error {
	// Prevent crashing in case of unhandled panic.
	defer func() {
		x := recover()
		if x == nil {
			return
		}
		metricPanics.Inc()
		slog.Error("unhandled panic", "panic", x)
		debug.PrintStack()
	}()

	slog.Info("trying to move transparency log forward")

	latestBuf, err := tlogclient.ops.ReadRemote("/latest")
	if err != nil {
		return fmt.Errorf("fetch new sumdb latest state: %v", err)
	}

	if err := forwardProcessLatest(latestBuf); err != nil {
		return fmt.Errorf("forwarding transparency log to latest position and processing modules: %v", err)
	}
	return nil
}

var forwardMutex sync.Mutex

func forwardProcessLatest(latestBuf []byte) error {
	// We can be called periodically and through Forward API call.
	forwardMutex.Lock()
	defer forwardMutex.Unlock()

	ts, ntree, modVersions, err := latestModules(latestBuf)
	if err != nil {
		return fmt.Errorf("new modules/versions for latest position: %v", err)
	}

	if ts.RecordsProcessed >= ntree.N {
		slog.Info("sumdb hasn't moved forward")
		return nil
	}

	if err := processModules(ts, ntree, modVersions); err != nil {
		return fmt.Errorf("processing new modules/versions: %v", err)
	}

	notify()

	return nil
}

func latestModules(latest []byte) (TreeState, tlog.Tree, []module.Version, error) {
	ntree, _, err := tlogclient.forward(latest)
	if err != nil {
		return TreeState{}, tlog.Tree{}, nil, fmt.Errorf("forwarding to new latest: %v", err)
	}

	ts := TreeState{ID: 1}
	if err := database.Get(context.Background(), &ts); err != nil {
		return ts, tlog.Tree{}, nil, fmt.Errorf("get treestate from database: %v", err)
	}

	id := ts.RecordsProcessed
	slog.Info("gathering new modules for tree", "oldposition", id, "newposition", ntree.N)

	var modversions []module.Version

	// Move tree forward, one tile at a time. tree.N is the size, so corresponds with
	// the next id to be filled.
	for id < ntree.N {
		const W = 256 // Tileheight is 2**8 (tileheight 8).

		tile := id / W
		tileEndID := (tile + 1) * W
		if ntree.N < tileEndID {
			// Tile not yet filled up.
			tileEndID = ntree.N
		}
		w := int(tileEndID - tile*W) // Number to request from this tile.

		t := tlog.Tile{H: 8, L: -1, N: tile, W: w}
		p := "/" + t.Path()
		data, err := tlogclient.ops.ReadRemote(p)
		if err != nil {
			return ts, tlog.Tree{}, nil, fmt.Errorf("reading data tile: %v", err)
		}

		// todo: better parser? existing code for parsing?
		l := strings.Split(string(data), "\n\n")
		if len(l) < int(w) {
			return ts, tlog.Tree{}, nil, fmt.Errorf("not enough data records in data tile, got %d, expected %d", len(l), w)
		}

		indexes := []int64{}
		for o := int(id % W); o < w; o++ {
			xid := tile*W + int64(o)
			indexes = append(indexes, tlog.StoredHashIndex(0, xid))
		}

		hashes, err := tlog.TileHashReader(ntree, &tlogclient.tileReader).ReadHashes(indexes)
		if err != nil {
			return ts, tlog.Tree{}, nil, fmt.Errorf("reading record hashes: %v", err)
		}

		for o := int(id % W); o < w; o++ {
			record := l[o]
			if o < len(l)-1 {
				record += "\n" // Restore line ending.
			}
			h := tlog.RecordHash([]byte(record))
			if h != hashes[0] {
				return ts, tlog.Tree{}, nil, fmt.Errorf("hash mismatch for record id %d, got %x, expect %x", id, h, hashes[0])
			}
			hashes = hashes[1:]

			var zeroversion, version module.Version
			for _, line := range strings.Split(strings.TrimRight(l[o], "\n"), "\n") {
				t := strings.Split(line, " ")
				if len(t) != 3 {
					return ts, tlog.Tree{}, nil, fmt.Errorf("invalid record line %q", line)
				}
				t[1] = strings.TrimSuffix(t[1], "/go.mod")
				v := module.Version{Path: t[0], Version: t[1]}
				if err := module.Check(v.Path, v.Version); err != nil {
					return ts, tlog.Tree{}, nil, fmt.Errorf("invalid module version %q %q: %v", v.Path, v.Version, err)
				}
				if version != zeroversion && version != v {
					return ts, tlog.Tree{}, nil, fmt.Errorf("multiple modules in record: %s and %s", version, v)
				}
				if version == zeroversion {
					pseudo := module.IsPseudoVersion(v.Version)
					ispre := semver.Prerelease(v.Version) != ""
					slog.Info("new module/version", "module", v.Path, "version", v.Version, "pseudo", pseudo, "prerelease", ispre)
					modversions = append(modversions, v)
				}
				version = v
			}

			id++
		}
	}
	return ts, ntree, modversions, nil
}

func processModules(ts TreeState, ntree tlog.Tree, modversions []module.Version) error {
	now := time.Now()
	var nprocessed int64
	var nupdates int
	var havehooks bool
	err := database.Write(context.Background(), func(tx *bstore.Tx) error {
		nprocessed = ntree.N - ts.RecordsProcessed
		if nprocessed != int64(len(modversions)) {
			return fmt.Errorf("internal error, nprocessed %d, len modversions %d", nprocessed, len(modversions))
		}

		ts.RecordsProcessed = ntree.N
		ts.Updated = now
		err := tx.Update(&ts)
		if err != nil {
			return fmt.Errorf("updating tree state")
		}

		// If we keep limited history of new modules/versions, cleanup old ones.
		if config.ModuleVersionHistorySize > 0 {
			n, err := bstore.QueryTx[ModuleVersion](tx).Count()
			if err != nil {
				return fmt.Errorf("counting current module versions in database: %v", err)
			}
			keep := config.ModuleVersionHistorySize
			if int64(n) < keep {
				keep = int64(n)
			}
			keep -= int64(len(modversions))
			if keep < int64(n) {
				if keep <= 0 {
					_, err := bstore.QueryTx[ModuleVersion](tx).Delete()
					if err != nil {
						return fmt.Errorf("deleting old module versions: %v", err)
					}
				} else {
					var keepID int64
					err := bstore.QueryTx[ModuleVersion](tx).SortDesc("ID").ForEach(func(mv ModuleVersion) error {
						if keep <= 0 {
							return bstore.StopForEach
						}
						keep--
						keepID = mv.ID
						return nil
					})
					if err != nil {
						return fmt.Errorf("walking old module versions: %v", err)
					}
					if _, err := bstore.QueryTx[ModuleVersion](tx).FilterLess("ID", keepID).Delete(); err != nil {
						return fmt.Errorf("deleting old module versions: %v", err)
					}
				}
			}
		}
		// Insert all we received this round.
		// todo: don't insert those beyond ModuleVersionHistorySize
		startID := ntree.N - int64(len(modversions))
		for i, mv := range modversions {
			pseudo := module.IsPseudoVersion(mv.Version)
			ispre := semver.Prerelease(mv.Version) != ""
			modvers := ModuleVersion{
				Module:      mv.Path,
				Version:     mv.Version,
				Pseudo:      pseudo,
				Prerelease:  ispre,
				LogRecordID: startID + int64(i),
			}
			if err := tx.Insert(&modvers); err != nil {
				return fmt.Errorf("inserting module version: %v", err)
			}
		}

		// For each new module/version, find matching subscriptions and gather updates.
		// We'll then sort them to order by version. Then we insert them into the database
		// for subsequent message sending.
		var updates []ModuleUpdate
		var hooks []Hook
	ModVersion:
		for i, mv := range modversions {
			p := mv.Path

			// Don't notify about anything with a prefix in the skip list. E.g. module mirrors.
			for _, m := range config.SkipModulePrefixes {
				if strings.HasPrefix(p, m) {
					continue ModVersion
				}
			}

		Path:
			for ; p != "" && p != "."; p = path.Dir(p) {
				// Don't notify about anything matching these exact module paths, e.g. github.com,
				// it would lead to many matches.
				if slices.Contains(config.SkipModulePaths, p) {
					continue Path
				}

				subs, err := bstore.QueryTx[Subscription](tx).FilterNonzero(Subscription{Module: p}).List()
				if err != nil {
					return fmt.Errorf("listing subscriptions for module: %v", err)
				}
				for _, sub := range subs {
					if !sub.BelowModule && p != mv.Path {
						continue
					}
					if !sub.Prerelease && semver.Prerelease(mv.Version) != "" {
						continue
					}
					if !sub.Pseudo && module.IsPseudoVersion(mv.Version) {
						continue
					}
					if !sub.OlderVersions {
						// Check most recent version we notified about.
						q := bstore.QueryTx[ModuleUpdate](tx)
						q.FilterNonzero(ModuleUpdate{UserID: sub.UserID, Module: mv.Path})
						q.SortDesc("Discovered")
						q.Limit(1)
						modup, err := q.Get()
						if err != nil && err != bstore.ErrAbsent {
							return fmt.Errorf("looking up most recent notified version for update: %v", err)
						}
						if err == nil && semver.Compare(modup.Version, mv.Version) <= 0 {
							continue
						}
					}

					user := User{ID: sub.UserID}
					if err := tx.Get(&user); err != nil {
						return fmt.Errorf("get user: %v", err)
					} else if sub.HookConfigID == 0 && (user.UpdatesUnsubscribed || user.Backoff >= BackoffPermanent) {
						continue
					}

					var h Hook
					if sub.HookConfigID != 0 {
						hc := HookConfig{ID: sub.HookConfigID}
						if err := tx.Get(&hc); err != nil {
							return fmt.Errorf("get webhook config: %v", err)
						}

						if hc.Disabled {
							slog.Debug("webhook config disabled, not notifying", "userid", user.ID, "hookconfig", hc.Name, "module", mv.Path, "version", mv.Version, "subscriptionpath", p)
							continue
						}

						h = Hook{
							UserID:       user.ID,
							HookConfigID: hc.ID,
							URL:          hc.URL, // Copy of URL for history.
							// NextAttempt will be updated below, for spreading over a 1-5 min interval.
							NextAttempt: time.Now(),
						}
						if err := tx.Insert(&h); err != nil {
							return fmt.Errorf("insert hook: %v", err)
						}
						slog.Debug("created webhook call for module update", "userid", user.ID, "hookconfig", hc.Name, "hookid", h.ID, "subscriptionpath", p, "module", mv.Path, "version", mv.Version)
						hooks = append(hooks, h)
					} else {
						slog.Info("found email subscription for module", "userid", user.ID, "path", p, "subscriptionpath", p, "module", mv.Path, "version", mv.Version, "subscription", sub)
					}

					modup := ModuleUpdate{
						UserID:         sub.UserID,
						SubscriptionID: sub.ID,
						LogRecordID:    startID + int64(i),
						Module:         mv.Path,
						Version:        mv.Version,
						HookID:         h.ID,
						HookConfigID:   h.HookConfigID,
					}
					updates = append(updates, modup)
				}
			}
		}

		sort.Slice(updates, func(i, j int) bool {
			a, b := updates[i], updates[j]
			if a.Module != b.Module {
				return a.Module < b.Module
			}
			return semver.Compare(a.Version, b.Version) < 0
		})
		slog.Info("inserting module updates", "nupdates", len(updates))
		for _, modup := range updates {
			if err := tx.Insert(&modup); err != nil {
				return fmt.Errorf("inserting module update: %v", err)
			}
		}
		nupdates = len(updates)

		// Spread out delivery of hooks over 1-5 minutes, depending on refresh interval.
		// todo: if subscription only cares about most recent version, keep only the highest version in case of multiple for a module.
		if len(hooks) > 1 {
			interval := config.SumDB.QueryLatestInterval
			if interval < time.Minute {
				interval = time.Minute
			} else if interval > 5*time.Minute {
				interval = 5 * time.Minute
			}
			interval /= time.Duration(len(hooks) - 1)
			for i := range hooks {
				hooks[i].NextAttempt = hooks[i].NextAttempt.Add(time.Duration(i) * interval)
				if err := tx.Update(&hooks[i]); err != nil {
					return fmt.Errorf("update next attempt for hook: %v", err)
				}
			}
		}
		havehooks = len(hooks) > 0

		return nil
	})
	if err != nil {
		return fmt.Errorf("updating database after new modules: %v", err)
	}

	if havehooks {
		kickHooksQueue()
	}

	metricTlogProcessed.Add(float64(nprocessed))
	metricTlogRecords.Set(float64(ntree.N))
	metricUpdateMatchesTotal.Add(float64(nupdates))
	return nil
}
