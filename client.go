// Copied and modified, see vendor/golang.org/x/mod/LICENSE and vendor/golang.org/x/mod/PATENTS
//
// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// A ClientOps provides the external operations
// (file caching, HTTP fetches, and so on) needed by the [Client].
// The methods must be safe for concurrent use by multiple goroutines.
type ClientOps interface {
	// ReadRemote reads and returns the content served at the given path
	// on the remote database server. The path begins with "/latest", "/lookup" or
	// "/tile/", and there is no need to parse the path in any way.
	// It is the implementation's responsibility to turn that path into a full URL
	// and make the HTTP request. ReadRemote should return an error for
	// any non-200 HTTP response status.
	ReadRemote(path string) ([]byte, error)

	// ReadCache reads and returns the content of the named cache file.
	// Any returned error will be treated as equivalent to the file not existing.
	// There can be arbitrarily many cache files, such as:
	//	serverName/lookup/pkg@version
	//	serverName/tile/8/1/x123/456
	ReadCache(file string) ([]byte, error)

	// WriteCache writes the named cache file.
	WriteCache(file string, data []byte)

	// Log prints the given log message (such as with log.Print)
	Log(msg string)

	// SecurityError prints the given security error log message.
	// The Client returns ErrSecurity from any operation that invokes SecurityError,
	// but the return value is mainly for testing. In a real program,
	// SecurityError should typically print the message and call log.Fatal or os.Exit.
	SecurityError(msg string)
}

// ErrSecurity is returned by [Client] operations that invoke Client.SecurityError.
var ErrSecurity = errors.New("security error: misbehaving server")

// A Client is a client connection to a checksum database.
// All the methods are safe for simultaneous use by multiple goroutines.
type Client struct {
	verifierKey string
	ops         ClientOps // access to operations in the external world

	didLookup uint32

	// one-time initialized data
	initOnce   sync.Once
	initErr    error          // init error, if any
	name       string         // name of accepted verifier
	verifiers  note.Verifiers // accepted verifiers (just one, but Verifiers for note.Open)
	tileReader tileReader
	tileHeight int

	tileCache parCache // cache of c.readTile, keyed by tile

	latestMu  sync.Mutex
	latest    tlog.Tree // latest known tree head
	latestMsg []byte    // encoded signed note for latest

	tileSavedMu sync.Mutex
	tileSaved   map[tlog.Tile]bool // which tiles have been saved using c.ops.WriteCache already
}

// NewClient returns a new [Client] using the given [ClientOps].
func NewClient(verifierKey string, ops ClientOps) *Client {
	return &Client{
		verifierKey: verifierKey,
		ops:         ops,
	}
}

// init initializes the client (if not already initialized)
// and returns any initialization error.
func (c *Client) init() error {
	c.initOnce.Do(c.initWork)
	return c.initErr
}

// initWork does the actual initialization work.
func (c *Client) initWork() {
	defer func() {
		if c.initErr != nil {
			c.initErr = fmt.Errorf("initializing sumdb.Client: %v", c.initErr)
		}
	}()

	c.tileReader.c = c
	if c.tileHeight == 0 {
		c.tileHeight = 8
	}
	c.tileSaved = make(map[tlog.Tile]bool)

	verifier, err := note.NewVerifier(strings.TrimSpace(c.verifierKey))
	if err != nil {
		c.initErr = err
		return
	}
	c.verifiers = note.VerifierList(verifier)
	c.name = verifier.Name()

	if c.latest.N == 0 {
		c.latest.Hash, err = tlog.TreeHash(0, nil)
		if err != nil {
			c.initErr = err
			return
		}
	}
}

// SetTileHeight sets the tile height for the Client.
// Any call to SetTileHeight must happen before the first call to [Client.Lookup].
// If SetTileHeight is not called, the Client defaults to tile height 8.
// SetTileHeight can be called at most once,
// and if so it must be called before the first call to Lookup.
func (c *Client) SetTileHeight(height int) {
	if atomic.LoadUint32(&c.didLookup) != 0 {
		panic("SetTileHeight used after Lookup")
	}
	if height <= 0 {
		panic("invalid call to SetTileHeight")
	}
	if c.tileHeight != 0 {
		panic("multiple calls to SetTileHeight")
	}
	c.tileHeight = height
}

const (
	msgPast = 1 + iota
	msgNow
	msgFuture
)

func (c *Client) forward(msg []byte) (tlog.Tree, int, error) {
	note, err := note.Open(msg, c.verifiers)
	if err != nil {
		return tlog.Tree{}, 0, fmt.Errorf("reading tree note: %v\nnote:\n%s", err, msg)
	}
	tree, err := tlog.ParseTree([]byte(note.Text))
	if err != nil {
		return tlog.Tree{}, 0, fmt.Errorf("reading tree: %v\ntree:\n%s", err, note.Text)
	}

	// Other lookups may be calling mergeLatest with other heads,
	// so c.latest is changing underfoot. We don't want to hold the
	// c.mu lock during tile fetches, so loop trying to update c.latest.
	c.latestMu.Lock()
	latest := c.latest
	latestMsg := c.latestMsg
	c.latestMu.Unlock()

	for {
		// If the tree head looks old, check that it is on our timeline.
		if tree.N < latest.N {
			if err := c.checkTrees(tree, msg, latest, latestMsg); err != nil {
				return tree, 0, err
			}
			if tree.N < latest.N {
				return tree, msgPast, nil
			}
			return tree, msgNow, nil
		}

		// The tree head looks new. Check that we are on its timeline and try to move our
		// timeline forward.
		if err := c.checkTrees(latest, latestMsg, tree, msg); err != nil {
			return tree, 0, err
		}

		// Install our msg if possible.
		// Otherwise we will go around again.
		c.latestMu.Lock()
		installed := false
		if c.latest == latest {
			installed = true
			c.latest = tree
			c.latestMsg = msg
		} else {
			latest = c.latest
			latestMsg = c.latestMsg
		}
		c.latestMu.Unlock()

		if installed {
			return tree, msgFuture, nil
		}
	}
}

// checkTrees checks that older (from olderNote) is contained in newer (from newerNote).
// If an error occurs, such as malformed data or a network problem, checkTrees returns that error.
// If on the other hand checkTrees finds evidence of misbehavior, it prepares a detailed
// message and calls SecurityError.
func (c *Client) checkTrees(older tlog.Tree, olderNote []byte, newer tlog.Tree, newerNote []byte) error {
	thr := tlog.TileHashReader(newer, &c.tileReader)
	h, err := tlog.TreeHash(older.N, thr)
	if err != nil {
		if older.N == newer.N {
			return fmt.Errorf("checking tree#%d: %v", older.N, err)
		}
		return fmt.Errorf("checking tree#%d against tree#%d: %v", older.N, newer.N, err)
	}
	if h == older.Hash {
		return nil
	}

	// Detected a fork in the tree timeline.
	// Start by reporting the inconsistent signed tree notes.
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "SECURITY ERROR\n")
	fmt.Fprintf(&buf, "go.sum database server misbehavior detected!\n\n")
	indent := func(b []byte) []byte {
		return bytes.Replace(b, []byte("\n"), []byte("\n\t"), -1)
	}
	fmt.Fprintf(&buf, "old database:\n\t%s\n", indent(olderNote))
	fmt.Fprintf(&buf, "new database:\n\t%s\n", indent(newerNote))

	// The notes alone are not enough to prove the inconsistency.
	// We also need to show that the newer note's tree hash for older.N
	// does not match older.Hash. The consumer of this report could
	// of course consult the server to try to verify the inconsistency,
	// but we are holding all the bits we need to prove it right now,
	// so we might as well print them and make the report not depend
	// on the continued availability of the misbehaving server.
	// Preparing this data only reuses the tiled hashes needed for
	// tlog.TreeHash(older.N, thr) above, so assuming thr is caching tiles,
	// there are no new access to the server here, and these operations cannot fail.
	fmt.Fprintf(&buf, "proof of misbehavior:\n\t%v", h)
	if p, err := tlog.ProveTree(newer.N, older.N, thr); err != nil {
		fmt.Fprintf(&buf, "\tinternal error: %v\n", err)
	} else if err := tlog.CheckTree(p, newer.N, newer.Hash, older.N, h); err != nil {
		fmt.Fprintf(&buf, "\tinternal error: generated inconsistent proof\n")
	} else {
		for _, h := range p {
			fmt.Fprintf(&buf, "\n\t%v", h)
		}
	}
	c.ops.SecurityError(buf.String())
	return ErrSecurity
}

// tileReader is a *Client wrapper that implements tlog.TileReader.
// The separate type avoids exposing the ReadTiles and SaveTiles
// methods on Client itself.
type tileReader struct {
	c *Client
}

func (r *tileReader) Height() int {
	return r.c.tileHeight
}

// ReadTiles reads and returns the requested tiles,
// either from the on-disk cache or the server.
func (r *tileReader) ReadTiles(tiles []tlog.Tile) ([][]byte, error) {
	// Read all the tiles in parallel.
	data := make([][]byte, len(tiles))
	errs := make([]error, len(tiles))
	var wg sync.WaitGroup
	for i, tile := range tiles {
		wg.Add(1)
		go func(i int, tile tlog.Tile) {
			defer wg.Done()
			defer func() {
				if e := recover(); e != nil {
					errs[i] = fmt.Errorf("panic: %v", e)
				}
			}()
			data[i], errs[i] = r.c.readTile(tile)
		}(i, tile)
	}
	wg.Wait()

	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}

	return data, nil
}

// tileCacheKey returns the cache key for the tile.
func (c *Client) tileCacheKey(tile tlog.Tile) string {
	return c.name + "/" + tile.Path()
}

// tileRemotePath returns the remote path for the tile.
func (c *Client) tileRemotePath(tile tlog.Tile) string {
	return "/" + tile.Path()
}

// readTile reads a single tile, either from the on-disk cache or the server.
func (c *Client) readTile(tile tlog.Tile) ([]byte, error) {
	type cached struct {
		data []byte
		err  error
	}

	result := c.tileCache.Do(tile, func() interface{} {
		// Try the requested tile in on-disk cache.
		data, err := c.ops.ReadCache(c.tileCacheKey(tile))
		if err == nil {
			c.markTileSaved(tile)
			return cached{data, nil}
		}

		// Try the full tile in on-disk cache (if requested tile not already full).
		// We only save authenticated tiles to the on-disk cache,
		// so the recreated prefix is equally authenticated.
		full := tile
		full.W = 1 << uint(tile.H)
		if tile != full {
			xdata, err := c.ops.ReadCache(c.tileCacheKey(full))
			if err == nil {
				c.markTileSaved(tile) // don't save tile later; we already have full
				return cached{xdata[:len(xdata)/full.W*tile.W], nil}
			}
		}

		// Try requested tile from server.
		data, err = c.ops.ReadRemote(c.tileRemotePath(tile))
		if err == nil {
			return cached{data, nil}
		}

		// Try full tile on server.
		// If the partial tile does not exist, it should be because
		// the tile has been completed and only the complete one
		// is available.
		if tile != full {
			data, err := c.ops.ReadRemote(c.tileRemotePath(full))
			if err == nil {
				// Note: We could save the full tile in the on-disk cache here,
				// but we don't know if it is valid yet, and we will only find out
				// about the partial data, not the full data. So let SaveTiles
				// save the partial tile, and we'll just refetch the full tile later
				// once we can validate more (or all) of it.
				return cached{data[:len(data)/full.W*tile.W], nil}
			}
		}

		// Nothing worked.
		// Return the error from the server fetch for the requested (not full) tile.
		return cached{nil, err}
	}).(cached)

	return result.data, result.err
}

// markTileSaved records that tile is already present in the on-disk cache,
// so that a future SaveTiles for that tile can be ignored.
func (c *Client) markTileSaved(tile tlog.Tile) {
	c.tileSavedMu.Lock()
	c.tileSaved[tile] = true
	c.tileSavedMu.Unlock()
}

// SaveTiles saves the now validated tiles.
func (r *tileReader) SaveTiles(tiles []tlog.Tile, data [][]byte) {
	c := r.c

	// Determine which tiles need saving.
	// (Tiles that came from the cache need not be saved back.)
	save := make([]bool, len(tiles))
	c.tileSavedMu.Lock()
	for i, tile := range tiles {
		if !c.tileSaved[tile] {
			save[i] = true
			c.tileSaved[tile] = true
		}
	}
	c.tileSavedMu.Unlock()

	for i, tile := range tiles {
		if save[i] {
			// If WriteCache fails here (out of disk space? i/o error?),
			// c.tileSaved[tile] is still true and we will not try to write it again.
			// Next time we run maybe we'll redownload it again and be
			// more successful.
			c.ops.WriteCache(c.name+"/"+tile.Path(), data[i])
		}
	}
}
