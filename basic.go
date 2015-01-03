package auth

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"strings"
)

import "github.com/codegangsta/negroni"

// BasicConfig defines options for HTTP Basic Authentication middleware.
type BasicConfig struct {
	// Validate is function to validate credentials
	Validate func(r *http.Request, username, password string) bool
	// UnauthorizedHandler is optional error handler to override default error handler.
	UnauthorizedHandler http.Handler
}

// Basic returns gohttp middleware
func Basic(config BasicConfig) func(http.Handler) http.Handler {
	if config.UnauthorizedHandler == nil {
		config.UnauthorizedHandler = http.HandlerFunc(defaultUnauthorizedHandler)
	}
	return func(next http.Handler) http.Handler {
		return &gohttpBasicAuth{config, next}
	}
}

// BasicNegroni returns negroni middleware
func BasicNegroni(config BasicConfig) negroni.Handler {
	if config.UnauthorizedHandler == nil {
		config.UnauthorizedHandler = http.HandlerFunc(defaultUnauthorizedHandler)
	}
	return &negroniBasicAuth{config}
}

// gohttp middleware
type gohttpBasicAuth struct {
	config BasicConfig
	next   http.Handler
}

// ServeHTTP implementation.
func (m *gohttpBasicAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	basicAuthImpl(m.config, w, r, m.next)
}

// negroni middleware
type negroniBasicAuth struct {
	config BasicConfig
}

// ServeHTTP implementation.
func (m *negroniBasicAuth) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	basicAuthImpl(m.config, w, r, next)
}

// basic auth implementation
func basicAuthImpl(config BasicConfig, w http.ResponseWriter, r *http.Request, next http.Handler) {
	// TODO url filter to allow public resources
	if validateBasicAuth(config, r) {
		next.ServeHTTP(w, r)
	} else {
		config.UnauthorizedHandler.ServeHTTP(w, r)
	}
}

// Validates the user:password combination provided in the Authorization header.
func validateBasicAuth(config BasicConfig, r *http.Request) bool {
	const basicScheme string = "Basic "

	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, basicScheme) {
		return false
	}

	str, err := base64.StdEncoding.DecodeString(header[len(basicScheme):])
	if err != nil {
		return false
	}

	creds := bytes.SplitN(str, []byte(":"), 2)
	if len(creds) != 2 {
		return false
	}

	return config.Validate(r, string(creds[0]), string(creds[1]))
}

// defaultUnauthorizedHandler provides a default HTTP 401 Unauthorized response.
func defaultUnauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}
