package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/mjl-/bstore"
	"github.com/mjl-/mox/smtpclient"
)

// Send a message to all users with updates we haven't notified about. Taking
// backoff and the interval into consideration.
func notify() {
	ctx := context.Background()

	userUpdates := map[int64][]ModuleUpdate{}
	err := bstore.QueryDB[ModuleUpdate](ctx, database).FilterEqual("MessageID", 0).ForEach(func(modup ModuleUpdate) error {
		userUpdates[modup.UserID] = append(userUpdates[modup.UserID], modup)
		return nil
	})
	if err != nil {
		logErrorx("gathering module updates to notify about", err)
		return
	}

	var smtpconn *smtpclient.Client
	defer func() {
		if smtpconn != nil {
			err := smtpconn.Close()
			logCheck(err, "closing submission connection")
		}
	}()

	for userID, updates := range userUpdates {
		log := slog.With("userid", userID)

		// Check if we should send to user, taking backoff into account, possibly trying to
		// get message flow again after a backoff.
		var u User
		var backoff bool
		err := database.Write(ctx, func(tx *bstore.Tx) error {
			var err error
			u, backoff, err = checkCanSend(tx, userID)
			return err
		})
		if err != nil {
			log.Error("checking if we can send to user", "err", err)
			return
		}
		if backoff {
			log.Error("backing off from sending")
			continue
		}

		loginToken := tokenSign(tokentypeLogin, time.Now(), u.ID)
		subject, text, html, err := composeModuleUpdates(u, loginToken, updates)
		if err != nil {
			log.Error("composing update notification text", "err", err)
			return
		}
		mailFrom, sendID, msg, eightbit, smtputf8, err := compose(false, u, "", subject, text, html)
		if err != nil {
			log.Error("composing update notification message", "err", err)
			return
		}

		// Wait until we can send, we may be ratelimiting.
		d := 5 * time.Second
		for !smtpCanSend() {
			// If we already have a connection, close it for now. Otherwise it will likely
			// timeout and the submission will fail.
			if smtpconn != nil {
				if err := smtpconn.Close(); err != nil {
					log.Error("closing smtp connection", "err", err)
				}
				smtpconn = nil
			}
			log.Info("waiting for rate limit on outgoing messages")
			time.Sleep(d)
			if d < 20*time.Second {
				d *= 2
			}
		}

		// We mark the message as sent before actually sending. Otherwise, we may end up
		// sending a user many messages if we encounter an error while marking as sent.
		var m Message
		err = database.Write(context.Background(), func(tx *bstore.Tx) error {
			m = Message{
				UserID: u.ID,
				Meta:   false,
				SendID: sendID,
			}
			if err := tx.Insert(&m); err != nil {
				return fmt.Errorf("inserting sent message: %v", err)
			}

			for _, up := range updates {
				up.MessageID = m.ID
				if err := tx.Update(&up); err != nil {
					return fmt.Errorf("updating sent module update: %v", err)
				}
			}
			return nil
		})
		if err != nil {
			log.Error("marking module updates as sent in database", "err", err)
			return
		}

		smtpTake()

		var senderr error
		if smtpconn == nil {
			dialctx, dialcancel := context.WithTimeout(ctx, 10*time.Second)
			smtpconn, senderr = smtpDial(dialctx)
			dialcancel()
		}
		if senderr == nil {
			submitctx, submitcancel := context.WithTimeout(ctx, 10*time.Second)
			senderr = smtpSubmit(submitctx, smtpconn, false, mailFrom, u.Email, msg, eightbit, smtputf8)
			submitcancel()
		}
		if senderr != nil {
			// todo: we could remove the message and mark the updates as not-notified
			log.Error("sending update notification message", "err", senderr)
			m.Error = fmt.Sprintf("submit: %s", senderr)
			if err := database.Update(context.Background(), &m); err != nil {
				log.Error("marking message submission failed", "err", err)
			}
		}
	}
}

func checkCanSend(tx *bstore.Tx, userID int64) (user User, backoff bool, rerr error) {
	log := slog.With("userid", userID)

	user = User{ID: userID}
	if err := tx.Get(&user); err != nil {
		return User{}, false, fmt.Errorf("get user: %v", err)
	}
	var interval time.Duration
	switch user.UpdateInterval {
	case IntervalImmediate:
	case IntervalHour:
		interval = time.Hour
	case IntervalDay:
		interval = 24 * time.Hour
	case IntervalWeek:
		interval = 7 * 24 * time.Hour
	default:
		return user, false, fmt.Errorf("unexpected interval %q", user.UpdateInterval)
	}
	if interval < config.EmailUpdateInterval {
		interval = config.EmailUpdateInterval
	}

	exists, err := bstore.QueryTx[Message](tx).FilterNonzero(Message{UserID: user.ID}).FilterGreater("Submitted", time.Now().Add(-interval)).Exists()
	if err != nil {
		return user, false, fmt.Errorf("check if we sent message in past hour: %v", err)
	} else if exists {
		return user, true, nil
	}
	if user.Backoff == BackoffNone || user.Backoff >= BackoffPermanent || time.Until(user.BackoffUntil) > 0 {
		return user, user.Backoff != BackoffNone, nil
	}

	// Check if we need to clear the backoff state. We look at the most recent
	// messages. If the most recent is not a DSN and it was sent more than 1 day ago
	// (likely no DSN coming in anymore), we clear the backoff. If the most recent
	// message was a DSN, and we haven't tried starting up again, we'll do that.
	m, err := bstore.QueryTx[Message](tx).FilterNonzero(Message{UserID: user.ID}).SortDesc("Submitted").Limit(1).Get()
	if err != nil {
		return user, false, fmt.Errorf("no historic message for user with backoff set?")
	}
	if m.Failed {
		if user.BackoffTried {
			log.Error("backofftried already set, but most recent is a dsn, suspect")
			return user, true, nil
		}
		user.BackoffTried = true
		if err := tx.Update(&user); err != nil {
			return user, false, fmt.Errorf("marking backofftried for user id %d: %v", user.ID, err)
		}
		if err := addUserLogf(tx, user.ID, "Trying to start sending message again after backoff for user id %d", user.ID); err != nil {
			return user, false, fmt.Errorf("adding to user log about marking backofftried for user id %d", user.ID)
		}
		return user, false, nil
	}

	// We are still in backoff, and we've sent a message in the past 24h, it just
	// hasn't failed yet, but we could get a DSN.
	if time.Since(m.Submitted) < 24*time.Hour {
		return user, true, nil
	}

	// Clear old backoff.
	user.Backoff = BackoffNone
	user.BackoffUntil = time.Time{}
	user.BackoffTried = false
	if err := tx.Update(&user); err != nil {
		return user, false, fmt.Errorf("clearing backoff from user: %v", err)
	}
	if err := addUserLogf(tx, user.ID, "Clearing backoff from user, most recent message was not dsn and sent more than 1 day ago"); err != nil {
		return user, false, fmt.Errorf("marking clearing of backoff for user: %v", err)
	}
	return user, false, nil
}
