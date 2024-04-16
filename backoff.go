package main

import (
	"fmt"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/smtp"
)

func markBackoff(tx *bstore.Tx, user *User, event, smtpEcode string) error {
	// We start/extend backing off from sending more messages. We don't look at whether
	// this is a permanent or temporary failure. We'll retry after a while anyway, best
	// to hold off until we know more. Backoff is potentially reset when we look at
	// whether we should send a message again.
	if user.Backoff == BackoffNone || time.Since(user.BackoffUntil) > 0 && user.Backoff < BackoffPermanent {
		if user.Backoff == BackoffNone {
			user.BackoffUntil = time.Now()
		}
		// Set new Backoff end time (unless already permanent).
		user.Backoff++
		// If we are likely blocklisted, backoff for a week. The blocklist is likely not
		// resolved in a day, and sending more messages may contribute to staying
		// blocklisted.
		if smtpEcode == "5."+smtp.SePol7DeliveryUnauth1 && user.Backoff < BackoffWeek {
			user.Backoff = BackoffWeek
		}
		if user.Backoff < BackoffPermanent {
			d := 24 * time.Hour
			if user.Backoff >= BackoffWeek {
				d *= 7
			}
			if user.Backoff >= BackoffMonth {
				d *= 31
			}
			user.BackoffUntil = user.BackoffUntil.Add(d)
		}
		// Reset whether we've "tried" after the end time. When we check if we can send,
		// we'll optimistically try again after the end time, to recover to regular
		// sending.
		user.BackoffTried = false
		if err := tx.Update(user); err != nil {
			return fmt.Errorf("starting/extending backoff for user: %v", err)
		}
		if err := addUserLogf(tx, user.ID, "Received delivery failure %q, starting/extending backoff until %s", event, user.BackoffUntil.UTC()); err != nil {
			return fmt.Errorf("marking dsn in userlog: %v", err)
		}
	} else if err := addUserLogf(tx, user.ID, "Received delivery failure %q, no backoff extension/start", event); err != nil {
		return fmt.Errorf("marking dsn in userlog: %v", err)
	}
	return nil
}
