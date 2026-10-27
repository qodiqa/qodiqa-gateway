package qodiqa

import (
	"errors"
	"fmt"
	"strings"
)

// Kind classifies an Error the way the JavaScript and Python SDKs classify theirs.
type Kind string

const (
	KindAuthentication Kind = "authentication" // 401
	KindAuthorization  Kind = "authorization"  // 403
	KindValidation     Kind = "validation"     // 400 / 422 / a local argument check
	KindNotFound       Kind = "not_found"      // 404
	KindRateLimit      Kind = "rate_limit"     // 429
	KindServer         Kind = "server"         // 5xx
	KindVerification   Kind = "verification"   // the gateway refused an artifact
	KindMFARequired    Kind = "mfa_required"   // operator step-up: MFA_REQUIRED / MFA_INVALID
	KindMFAEnrollment  Kind = "mfa_enrollment" // MFA_ENROLLMENT_REQUIRED
	KindMFALocked      Kind = "mfa_locked"     // MFA_LOCKED
	KindNetwork        Kind = "network"        // the request never got an answer
	KindTimeout        Kind = "timeout"        // the whole call took longer than the configured timeout
	KindOther          Kind = "other"          // any other HTTP status
)

// Error is every failure of a call: an HTTP error answer (Status > 0), a transport failure, or a local argument error.
type Error struct {
	Kind       Kind
	Status     int // HTTP status, 0 when there was no answer
	Reason     string
	Message    string
	RequestID  string
	Details    map[string]any
	RetryAfter int // seconds the server asked to wait, 0 when it did not
	Err        error
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString(e.Message)
	if e.Status > 0 {
		fmt.Fprintf(&b, " (HTTP %d", e.Status)
		if e.Reason != "" && e.Reason != "UNKNOWN" {
			fmt.Fprintf(&b, ", %s", e.Reason)
		}
		b.WriteString(")")
	}
	if e.RequestID != "" {
		fmt.Fprintf(&b, " [request %s]", e.RequestID)
	}
	return b.String()
}

// Unwrap returns the underlying transport error, if any.
func (e *Error) Unwrap() error { return e.Err }

// AsError returns the *Error inside err, if there is one.
func AsError(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// verificationReasons are the gateway's artifact-rejection reasons (an artifact refusal is a verification error whatever the HTTP status).
var verificationReasons = map[string]bool{
	"INVALID_ARTIFACT": true, "INVALID_SIGNATURE": true, "FUTURE_TIMESTAMP": true, "EXPIRED": true, "TIME_SKEW_EXCEEDED": true,
	"KEY_REVOKED": true, "KEY_ARCHIVED": true, "KEY_DEPRECATED": true, "KEY_NOT_YET_ACTIVE": true, "KEY_STATUS_UNKNOWN": true,
	"REQUEST_MISMATCH": true, "REPLAY_DETECTED": true,
}

func classify(status int, reason string) Kind {
	switch {
	case reason == "MFA_REQUIRED" || reason == "MFA_INVALID":
		return KindMFARequired
	case reason == "MFA_ENROLLMENT_REQUIRED":
		return KindMFAEnrollment
	case reason == "MFA_LOCKED":
		return KindMFALocked
	case status == 401 || reason == "UNAUTHORIZED" || reason == "UNAUTHENTICATED":
		return KindAuthentication
	case verificationReasons[reason]:
		return KindVerification
	case status == 403 || reason == "FORBIDDEN":
		return KindAuthorization
	case status == 404 || reason == "NOT_FOUND":
		return KindNotFound
	case status == 429:
		return KindRateLimit
	case status == 400 || status == 422:
		return KindValidation
	case status >= 500:
		return KindServer
	}
	return KindOther
}

func validationError(format string, a ...any) *Error {
	return &Error{Kind: KindValidation, Status: 0, Reason: "INVALID_ARGUMENT", Message: fmt.Sprintf(format, a...)}
}
