package auth

import (
	"context"
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
	config = config.SetDefaults()
	return func(next http.Handler) http.Handler {
		return &middleware{
			config: config,
			next:   next,
		}
	}
}

// RequireAdmin creates auth middleware that authenticates only admin users.
func RequireAdmin(config *Config) func(http.Handler) http.Handler {
	config = config.SetDefaults()
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
		SendError(w, err)
	}
}

// Validates auth header or auth_token.
func (m *middleware) authenticate(r *http.Request) (context.Context, *Error) {
	var h = r.Header.Get(authorizationHeader)
	if len(h) > 0 {
		return m.validateHeader(r, h)
	}

	cookie, err := r.Cookie(m.config.TokenCookie)
	if err == nil && cookie != nil {
		return m.validateJWT(r, cookie.Value)
	}

	// from query string
	token := r.URL.Query().Get(m.config.TokenKey)
	if len(token) > 0 {
		return m.validateJWT(r, token)
	}

	return nil, ErrBadAuthorizationHeader
}

// Validates authorization header.
func (m *middleware) validateHeader(r *http.Request, auth string) (context.Context, *Error) {
	scheme, token, err := parseAuthorizationHeader(auth)
	if err != nil {
		return nil, err
	}

	switch scheme {
	case schemeBasic:
		return m.validateBasicAuth(r)
	case schemeBearer:
		return m.validateJWT(r, token)
	default:
		return nil, ErrUnsupportedAuthScheme
	}
}

func parseAuthorizationHeader(auth string) (scheme string, token string, err *Error) {
	if len(auth) == 0 {
		err = ErrBadAuthorizationHeader
		return
	}
	var f = strings.Fields(auth)
	if len(f) != 2 {
		err = ErrBadAuthorizationHeader
		return
	}

	scheme = strings.ToLower(f[0])
	token = f[1]

	if scheme == schemeBasic || scheme == schemeBearer {
		return
	}

	err = ErrUnsupportedAuthScheme
	return
}

func (m *middleware) validateBasicAuth(r *http.Request) (context.Context, *Error) {
	username, password, ok := r.BasicAuth()
	if !ok {
		return nil, ErrBadAuthorizationHeader
	}

	user, err := m.config.UserStore.ValidateCredentials(r.Context(), username, password)
	if err != nil {
		return nil, ErrBadCredentials.WithCause(err)
	}

	return m.validateUser(r, user)
}

func (m *middleware) validateJWT(r *http.Request, tokenString string) (context.Context, *Error) {
	_, user, err := validateJWT(m.config, r, tokenString)
	if err != nil {
		return nil, err
	}

	return m.validateUser(r, user)
}

func validateJWT(config *Config, r *http.Request, tokenString string) (*Token, User, *Error) {
	ip := getClientIP(r)
	if ip == "127.0.0.1" && len(r.Header.Get("X-Forwarded-For")) > 0 {
		ip = ""
	}
	token, err := parseToken(config, tokenString, ip, false)
	if err != nil {
		return nil, nil, err
	}

	user, error := config.UserStore.FindUserByID(r.Context(), token.UserID)
	if error != nil {
		return nil, nil, ErrUserNotFound.WithCause(error)
	}

	return token, user, nil
}

func (m *middleware) validateUser(r *http.Request, user User) (context.Context, *Error) {
	err := m.checkUser(user)
	if err != nil {
		return nil, err
	}
	return WithUser(r.Context(), user), nil
}

func (m *middleware) checkUser(user User) *Error {
	if m.requireAdmin && !user.IsAdmin() {
		return ErrNotAdmin
	}
	return nil
}
