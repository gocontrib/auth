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

func (err *Error) cause(cause error) *Error {
	result := &Error{}
	*result = *err
	result.Cause = cause
	return err
}

var (
	errBadAuthorizationHeader = &Error{
		Code:    "AUTH-BAD-AUTHORIZATION-HEADER",
		Status:  http.StatusUnauthorized,
		Message: "Invalid authorization header",
	}
	errUnsupportedAuthScheme = &Error{
		Code:    "AUTH-UNSUPPORTED-SCHEME",
		Status:  http.StatusUnauthorized,
		Message: "Unsupported authentication scheme",
	}
	errInvalidToken = &Error{
		Code:    "AUTH-INVALID-TOKEN",
		Status:  http.StatusUnauthorized,
		Message: "User token is invalid, please re-authenticate",
	}
	errInvalidIssuer = &Error{
		Code:    "AUTH-INVALID-ISSUER",
		Status:  http.StatusUnauthorized,
		Message: "User token was issued from another host",
	}
	errInvalidClientIP = &Error{
		Code:    "AUTH-INVALID-CLIENT-IP",
		Status:  http.StatusUnauthorized,
		Message: "User token was issued for another IP address",
	}
	errNotAdmin = &Error{
		Code:    "AUTH-NOT-ADMIN",
		Status:  http.StatusForbidden,
		Message: "You need admin privileges to make this API call",
	}
	errMalformedContent = &Error{
		Code:    "AUTH-BAD-CONTENT",
		Status:  http.StatusBadRequest,
		Message: "Malformed content",
	}
	errBadCredentials = &Error{
		Code:    "AUTH-BAD-CREDENTIALS",
		Status:  http.StatusUnauthorized,
		Message: "Invalid user credentials",
	}
	errUserNotFound = &Error{
		Code:    "AUTH-USER-NOT-FOUND",
		Status:  http.StatusUnauthorized,
		Message: "User not found",
	}
	errUnsupportedContentType = &Error{
		Code:    "AUTH-UNSUPPORTED-CONTENT-TYPE",
		Status:  http.StatusUnsupportedMediaType,
		Message: "Unrecognized data format",
	}
	errEncodeTokenFailed = &Error{
		Code:    "AUTH-ENCODE-TOKEN-FAILED",
		Status:  http.StatusUnauthorized,
		Message: "Cannot encode user token",
	}
)
