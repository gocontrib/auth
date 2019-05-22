package auth

import (
	"net/http"
)

type Error struct {
	Code    string `json:"error_code,omitempty"`
	Message string `json:"error_message,omitempty"`
	Status  int    `json:"status"`
	Cause   error  `json:"cause,omitempty"`
}

func (err *Error) Error() string {
	return err.Message
}

func (err *Error) WithCause(cause error) *Error {
	return &Error{
		Code:    err.Code,
		Message: err.Message,
		Status:  err.Status,
		Cause:   cause,
	}
}

var (
	ErrBadAuthorizationHeader = &Error{
		Code:    "AUTH-BAD-AUTHORIZATION-HEADER",
		Status:  http.StatusUnauthorized,
		Message: "Invalid authorization header",
	}
	ErrUnsupportedAuthScheme = &Error{
		Code:    "AUTH-UNSUPPORTED-SCHEME",
		Status:  http.StatusUnauthorized,
		Message: "Unsupported authentication scheme",
	}
	ErrInvalidToken = &Error{
		Code:    "AUTH-INVALID-TOKEN",
		Status:  http.StatusUnauthorized,
		Message: "User token is invalid, please re-authenticate",
	}
	ErrMissingUserID = &Error{
		Code:    "AUTH-INVALID-TOKEN",
		Status:  http.StatusUnauthorized,
		Message: "User token is missing user_id field",
	}
	ErrMissingExp = &Error{
		Code:    "AUTH-INVALID-TOKEN",
		Status:  http.StatusUnauthorized,
		Message: "User token is missing exp field",
	}
	ErrInvalidIssuer = &Error{
		Code:    "AUTH-INVALID-ISSUER",
		Status:  http.StatusUnauthorized,
		Message: "User token was issued from another host",
	}
	ErrInvalidClientIP = &Error{
		Code:    "AUTH-INVALID-CLIENT-IP",
		Status:  http.StatusUnauthorized,
		Message: "User token was issued for another IP address",
	}
	ErrNotAdmin = &Error{
		Code:    "AUTH-NOT-ADMIN",
		Status:  http.StatusForbidden,
		Message: "You need admin privileges to make this API call",
	}
	ErrMalformedContent = &Error{
		Code:    "AUTH-BAD-CONTENT",
		Status:  http.StatusBadRequest,
		Message: "Malformed content",
	}
	ErrBadCredentials = &Error{
		Code:    "AUTH-BAD-CREDENTIALS",
		Status:  http.StatusUnauthorized,
		Message: "Invalid user credentials",
	}
	ErrUserNotFound = &Error{
		Code:    "AUTH-USER-NOT-FOUND",
		Status:  http.StatusUnauthorized,
		Message: "User not found",
	}
	ErrUnsupportedContentType = &Error{
		Code:    "AUTH-UNSUPPORTED-CONTENT-TYPE",
		Status:  http.StatusUnsupportedMediaType,
		Message: "Unrecognized data format",
	}
	ErrEncodeTokenFailed = &Error{
		Code:    "AUTH-ENCODE-TOKEN-FAILED",
		Status:  http.StatusUnauthorized,
		Message: "Cannot encode user token",
	}
	ErrBadState = &Error{
		Code:    "AUTH-INTERNAL-SERVER-ERROR",
		Status:  http.StatusInternalServerError,
		Message: "Internal server error",
	}
)
