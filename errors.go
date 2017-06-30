package auth

import "errors"

var (
	errNoAuthorizationHeader  = errors.New("Authorization header is not set")
	errBadAuthorizationHeader = errors.New("Invalid authorization header")
	errUnsupportedAuthScheme  = errors.New("Unsupported authorization scheme")
	errInvalidToken           = errors.New("Invalid auth token")
	errInvalidIssuer          = errors.New("This token was issued from another host")
	errInvalidClientIP        = errors.New("This token was issued for another IP address")
)
