package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"strings"
)

const (
	schemeBasic         = "basic"
	schemeBearer        = "bearer"
	authorizationHeader = "Authorization"
)

// RequireUser creates auth middleware with given configuration.
func RequireUser(config *Config) func(http.Handler) http.Handler {
	config = config.setDefaults()
	return func(next http.Handler) http.Handler {
		return &middleware{
			config: config,
			next:   next,
		}
	}
}

// RequireAdmin creates auth middleware that authenticates only admin users.
func RequireAdmin(config *Config) func(http.Handler) http.Handler {
	config = config.setDefaults()
	return func(next http.Handler) http.Handler {
		return &middleware{
			config:       config,
			next:         next,
			requireAdmin: true,
		}
	}
}

type middleware struct {
	config       *Config
	next         http.Handler
	requireAdmin bool
}

// ServeHTTP implementation.
func (m *middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, err := m.authenticate(r)
	if err == nil {
		if ctx != nil && ctx != r.Context() {
			r = r.WithContext(ctx)
		}
		m.next.ServeHTTP(w, r)
	} else {
		sendError(w, err)
	}
}

// Validates auth header or auth_token.
func (m *middleware) authenticate(r *http.Request) (context.Context, *Error) {
	var h = r.Header.Get(authorizationHeader)
	if len(h) > 0 {
		return m.validateHeader(r, h)
	}

	// auth token as part of url
	if r.Method == "GET" {
		var token = r.URL.Query().Get(m.config.TokenKey)
		if len(token) > 0 {
			return m.jwtHandler(r, token)
		}
	}

	return nil, errBadAuthorizationHeader
}

// Validates authorization header.
func (m *middleware) validateHeader(r *http.Request, auth string) (context.Context, *Error) {
	if len(auth) == 0 {
		return nil, errBadAuthorizationHeader
	}

	var f = strings.Fields(auth)
	if len(f) != 2 {
		return nil, errBadAuthorizationHeader
	}

	var scheme = strings.ToLower(f[0])
	var token = f[1]

	switch scheme {
	case schemeBasic:
		return m.basicHandler(r, token)
	case schemeBearer:
		return m.jwtHandler(r, token)
	default:
		return nil, errUnsupportedAuthScheme
	}
}

func (m *middleware) basicHandler(r *http.Request, tokenString string) (context.Context, *Error) {
	var str, err = base64.StdEncoding.DecodeString(tokenString)
	if err != nil {
		return nil, errBadAuthorizationHeader.cause(err)
	}

	creds := bytes.SplitN(str, []byte(":"), 2)
	userName := string(creds[0])
	user, err := m.config.UserStore.ValidateCredentials(userName, string(creds[1]))
	if err != nil {
		return nil, errBadCredentials.cause(err)
	}

	return m.validateUser(r, user)
}

func (m *middleware) jwtHandler(r *http.Request, tokenString string) (context.Context, *Error) {
	token, err := parseToken(m.config, tokenString, getClientIP(r), false)
	if err != nil {
		return nil, err
	}

	user, error := m.config.UserStore.FindUserByID(token.UserID)
	if error != nil {
		return nil, errUserNotFound.cause(error)
	}

	return m.validateUser(r, user)
}

func (m *middleware) validateUser(r *http.Request, user User) (context.Context, *Error) {
	err := m.checkUser(user)
	if err != nil {
		return nil, err
	}
	return withUser(r.Context(), user), nil
}

func (m *middleware) checkUser(user User) *Error {
	if m.requireAdmin && !user.IsAdmin() {
		return errNotAdmin
	}
	return nil
}
