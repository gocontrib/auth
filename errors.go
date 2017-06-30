package auth

import "errors"

var (
	errNoAuthorizationHeader  = errors.New("Authorization header is not set")
	errBadAuthorizationHeader = errors.New("Invalid authorization header is not set")
	errInvalidToken = errors.New("The token isn't valid")
	errJwtNoUserID            = errors.New("JWT has no user_id claim")
)
