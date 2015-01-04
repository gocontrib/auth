package auth

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/codegangsta/negroni"
)

const (
	schemeBasic = "Basic"
)

// Config defines options for authentication middleware.
type Config struct {
	// Validate is function to validate credentials
	Validate func(r *http.Request, username, password string) bool
	// ValidateCustom is function to validate custom authorization scheme
	ValidateCustom func(r *http.Request, scheme, custom string) bool
	// UnauthorizedHandler is optional error handler to override default error handler.
	UnauthorizedHandler http.Handler
}

func (config Config) setDefaults() Config {
	if config.UnauthorizedHandler == nil {
		config.UnauthorizedHandler = http.HandlerFunc(defaultUnauthorizedHandler)
	}
	return config
}

// Middleware returns gohttp auth middleware.
func Middleware(config Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return Handler(config, next)
	}
}

// Handler creates auth middleware http handler.
func Handler(config Config, next http.Handler) http.Handler {
	return &gohttpMiddleware{config.setDefaults(), next}
}

// Negroni returns negroni auth middleware.
func Negroni(config Config) negroni.Handler {
	return &negroniMiddleware{config.setDefaults()}
}

// gohttp middleware
type gohttpMiddleware struct {
	config Config
	next   http.Handler
}

// ServeHTTP implementation.
func (m *gohttpMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authImpl(m.config, w, r, m.next)
}

// negroni middleware
type negroniMiddleware struct {
	config Config
}

// ServeHTTP implementation.
func (m *negroniMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	authImpl(m.config, w, r, next)
}

// auth implementation
func authImpl(config Config, w http.ResponseWriter, r *http.Request, next http.Handler) {
	if validate(config, r) {
		next.ServeHTTP(w, r)
	} else {
		config.UnauthorizedHandler.ServeHTTP(w, r)
	}
}

// Validates the user:password combination provided in the Authorization header.
func validate(config Config, r *http.Request) bool {

	h := r.Header.Get("Authorization")
	f := strings.Fields(h)
	if len(h) == 0 || len(f) != 2 {
		return false
	}

	if f[0] == schemeBasic {
		str, err := base64.StdEncoding.DecodeString(f[1])
		if err != nil {
			return false
		}

		creds := bytes.SplitN(str, []byte(":"), 2)

		return config.Validate(r, string(creds[0]), string(creds[1]))
	}

	if config.ValidateCustom != nil {
		return config.ValidateCustom(r, f[0], f[1])
	}

	return false
}

// defaultUnauthorizedHandler provides a default HTTP 401 Unauthorized response.
func defaultUnauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}
