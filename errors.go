package auth

import "errors"

var (
	errNoAuthorizationHeader  = errors.New("Authorization header is not set")
	errBadAuthorizationHeader = errors.New("Invalid authorization header")
	errUnsupportedAuthScheme  = errors.New("Unsupported authorization scheme")
	errInvalidToken           = errors.New("The token isn't valid")
)
