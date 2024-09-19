package main

import (
	"fmt"
	"time"
)

type TreeState struct {
	ID      int64     // Singleton with ID 1
	Updated time.Time `bstore:"default now"`
	// Size of tree when we started.
	RecordsInitial int64
	// Tree size that we consider ourselves up to date with.
	RecordsProcessed int64

	// We error out if we're launched in non-test-mode on a test tree state and vice versa.
	Test bool
}

type User struct {
	ID int64

	// Cannot be changed, users must create a new account instead. todo: improve
	Email string `bstore:"nonzero,unique"`

	// Like email, but with a simplified localpart to prevent duplicate account signup
	// attempts through the website.
	SimplifiedEmail string `bstore:"index"`

	SaltedHashedPassword string `json:"-"`

	PasswordResetToken string `bstore:"index" json:"-"`

	// If empty, user has been verified. Otherwise, we won't send notifications yet.
	VerifyToken string `bstore:"index" json:"-"`

	// Link with either of this in each email, including List-Unsubscribe and one-click
	// unsubscribe, for quick unsubscribe in case start considering this spam.
	MetaUnsubscribeToken    string `bstore:"index" json:"-"`
	UpdatesUnsubscribeToken string `bstore:"index" json:"-"`

	// If set, no more update notification emails are sent. We still send meta messages
	// for password resets, etc. We assume those are intended.
	MetaUnsubscribed    bool // If set, we won't send verify/password reset emails.
	UpdatesUnsubscribed bool // If set, we won't send update emails.

	// User can configure how long should be between email messages.
	// Subject to minimum setting in configuration.
	// todo: we hold off sending now, but don't schedule sending immediately when interval has past yet...
	UpdateInterval Interval `bstore:"nonzero"`

	// After sending emails with module updates, we can receive back a DSN, about
	// failed delivery. If that happens, we backoff from sending more messages for a
	// while (BackoffUntil). After that time, we'll try sending one message again
	// (BackoffTried). Perhaps the failure was temporary. If we get another error, we
	// extend the backoff for a longer period, possibly permanently (Backoff). We don't
	// take backoff into account when sending "meta" messages (about password resets,
	// etc). When finding an update for a subscription, we check if we should send. If
	// our try to start up sending again wasn't met with a DSN within 2 days, we can
	// clear the backoff again.
	Backoff BackoffState `json:"-"`

	// If backoff is active (BackoffCounter > 0), the time until we won't send new
	// messages. This is extended if an attempt to restart sending resulted in a DSN
	// again.
	BackoffUntil time.Time `json:"-"`

	// If a message has been send again while backoff active but after BackoffUntil.
	// This is an attempt to start up sending again. If no DSN comes in within 2 days,
	// the backoff is cleared when we check if we can send a message again.
	BackoffTried bool `json:"-"`
}

// How often a user wants to receive update notification email messages.
type Interval string

const (
	IntervalImmediate Interval = "immediate"
	IntervalHour      Interval = "hour"
	IntervalDay       Interval = "day"
	IntervalWeek      Interval = "week"
)

// How to long to backoff before trying to send another message again. Set and
// extended when we receive a DSN. Cleared when a message didn't result in a DSN
// anymore.
type BackoffState byte

const (
	BackoffNone BackoffState = iota
	BackoffDay
	BackoffWeek
	BackoffMonth
	BackoffPermanent
)

func (b BackoffState) String() string {
	switch b {
	case BackoffNone:
		return "none"
	case BackoffDay:
		return "day"
	case BackoffWeek:
		return "week"
	case BackoffMonth:
		return "month"
	case BackoffPermanent:
		return "permanent"
	}
	return fmt.Sprintf("(unknown backoffstate %d)", b)
}

// UserLog is a line of history about a change to the user account.
type UserLog struct {
	ID     int64
	UserID int64     `bstore:"nonzero,ref User,index UserID+Time"`
	Time   time.Time `bstore:"nonzero,default now"`
	Text   string    `bstore:"nonzero"`
}

// Subscription to a module. New versions will cause an Update to be registered and sent.
type Subscription struct {
	ID     int64
	UserID int64 `bstore:"nonzero,ref User" json:"-"`

	// Full path to subscribe to, e.g. github.com/mjl-.
	// The transparency log can have entries for various upper/lower case variants.
	// Easiest to care only about the canonical name.
	Module string `bstore:"nonzero"`

	// If set, we also match module paths that are below the subscribed module.
	BelowModule bool

	// If set, we also send updates about added versions that are older than what seen
	// previously. Can happen when multiple tags (versions) are pushed and old ones are
	// fetched later.
	OlderVersions bool

	// No pre-release version, such as "v1.2.3-rc1", or "v1.2.3-0.20240214164601-39bfa4338a12".
	Prerelease bool

	// No pseudo versions like "v0.0.0-20240214164601-39bfa4338a12".
	Pseudo bool

	Comment string // Comment by user, to explain to future self why this is being monitored.

	// If nonzero, don't deliver email message, but make a webhook call.
	HookConfigID int64 `bstore:"ref HookConfig"`
}

// HookConfig has the configured URL for deliveries by webhook.
type HookConfig struct {
	ID     int64
	UserID int64 `bstore:"unique UserID+Name"`

	Name     string      `bstore:"nonzero"`
	URL      string      `bstore:"nonzero"` // URL to POST JSON body to.
	Headers  [][2]string // Headers to send in request.
	Disabled bool
}

// Hook represents the (scheduled) delivery of a module update.
type Hook struct {
	ID           int64
	UserID       int64     `bstore:"ref User,index UserID+NextAttempt"` // Index for listing recent hooks.
	HookConfigID int64     `bstore:"nonzero,ref HookConfig"`
	URL          string    // Copied from webhook config.
	Queued       time.Time `bstore:"default now"`
	LastResult   time.Time
	Attempts     int          // Start with 0. Increased each time, determines the next interval in case of errors.
	NextAttempt  time.Time    `bstore:"default now"`
	Done         bool         `bstore:"index Done+NextAttempt"` // Index for quickly finding next work to do.
	Results      []HookResult // From old attempts to recent.
}

// HookResult is the result of one attempt at a webhook delivery.
type HookResult struct {
	StatusCode int // Successful if 2xx.
	Error      string
	Response   string // Max 256 bytes, only if text/plain or application/json.
	Start      time.Time
	DurationMS int64
}

// ModuleUpdate is a registered update for a module for a subscription.
type ModuleUpdate struct {
	ID             int64
	UserID         int64     `bstore:"nonzero,ref User,index UserID+Module+Discovered"`
	SubscriptionID int64     `bstore:"nonzero"` // No reference, subscriptions may be deleted.
	LogRecordID    int64     // As found in transparency log.
	Discovered     time.Time `bstore:"default now"`
	Module         string    `bstore:"nonzero"`
	Version        string    `bstore:"nonzero"`

	// If 0, not yet sent. Only relevant when HookID is 0, otherwise this is a webhook
	// call. We can suppress sending when recent messages have failed, or when our send
	// rate has been too high. Index for enumerating updates that weren't notified
	// about yet.
	MessageID int64 `bstore:"index"`

	// If nonzero, this is a webhook. The Hook record may have been cleaned up, but the ID
	// remains, hence no ref.
	HookID int64 `bstore:"index HookID+MessageID"`

	HookConfigID int64
}

// Message is sent to a user, with 1 or more module updates. Before we send, we
// check that the user doesn't have backoff active, and hasn't had too many
// messages recently.
type Message struct {
	ID     int64
	UserID int64 `bstore:"nonzero,ref User,index UserID+Meta+Submitted,index UserID+Submitted"`
	Meta   bool  // Like signup or password reset, instead of notification about module updates.

	// Localpart of message-id, used in mail from when sending, so bounces will have it
	// in Delivered-To, which we use for matching DSNs or webhook calls.
	// For submission, this is set when composing. For webapi, this is set after sending.
	SendID string `bstore:"index"`
	// For getting recent messages.
	Submitted        time.Time `bstore:"nonzero,default now"`
	Modified         time.Time `bstore:"nonzero,default now"`
	Failed           bool      // As notified through DSN.
	TemporaryFailure bool      // Otherwise permanent failure to deliver.

	// Details of error. Can also be set when submission failed (i.e. local error).
	Error   string
	DSNData string
	History []string // All events about delivery.
}

// ModuleVersion was (recently) encountered in the transparency log. We can keep a
// configurable number of most recent module versions around.
type ModuleVersion struct {
	ID          int64
	Module      string `bstore:"nonzero,unique Module+Version"`
	Version     string `bstore:"nonzero"`
	Pseudo      bool
	Prerelease  bool
	LogRecordID int64     // As found in transparency log.
	Discovered  time.Time `bstore:"nonzero,default now"`
}
