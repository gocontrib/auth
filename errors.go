package auth

import (
	"net/http"
)

type Error struct {
	ID      string `json:"id"`
	Status  int    `json:"status"`
	Message string `json:"message,omitempty"`
	Cause   string `json:"cause,omitempty"`
}

func (err *Error) Error() string {
	return err.Message
}

func (err *Error) cause(cause error) *Error {
	result := &Error{}
	*result = *err
	result.Cause = cause.Error()
	return err
}

var (
	errBadAuthorizationHeader = &Error{
		ID:      "AUTH-BAD-AUTHORIZATION-HEADER",
		Status:  http.StatusUnauthorized,
		Message: "Invalid authorization header",
	}
	errUnsupportedAuthScheme = &Error{
		ID:      "AUTH-UNSUPPORTED-SCHEME",
		Status:  http.StatusUnauthorized,
		Message: "Unsupported authentication scheme",
	}
	errInvalidToken = &Error{
		ID:      "AUTH-INVALID-TOKEN",
		Status:  http.StatusUnauthorized,
		Message: "User token is invalid, please re-authenticate",
	}
	errInvalidIssuer = &Error{
		ID:      "AUTH-INVALID-ISSUER",
		Status:  http.StatusUnauthorized,
		Message: "User token was issued from another host",
	}
	errInvalidClientIP = &Error{
		ID:      "AUTH-INVALID-CLIENT-IP",
		Status:  http.StatusUnauthorized,
		Message: "User token was issued for another IP address",
	}
	errNotAdmin = &Error{
		ID:      "AUTH-NOT-ADMIN",
		Status:  http.StatusUnauthorized,
		Message: "You need admin privileges to make this API call",
	}
	errMalformedContent = &Error{
		ID:      "AUTH-BAD-CONTENT",
		Status:  http.StatusBadRequest,
		Message: "Malformed content",
	}
	errBadCredentials = &Error{
		ID:      "AUTH-BAD-CREDENTIALS",
		Status:  http.StatusUnauthorized,
		Message: "Invalid user credentials",
	}
	errUserNotFound = &Error{
		ID:      "AUTH-USER-NOT-FOUND",
		Status:  http.StatusUnauthorized,
		Message: "User not found",
	}
	errUnsupportedContentType = &Error{
		ID:      "AUTH-UNSUPPORTED-CONTENT-TYPE",
		Status:  http.StatusUnsupportedMediaType,
		Message: "Unrecognized data format",
	}
	errEncodeTokenFailed = &Error{
		ID:      "AUTH-ENCODE-TOKEN-FAILED",
		Status:  http.StatusUnauthorized,
		Message: "Cannot encode user token",
	}
)
