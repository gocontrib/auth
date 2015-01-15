package auth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gocontrib/context"
	"github.com/gorilla/securecookie"
)

const (
	schemeBasic  = "basic"
	schemeBearer = "bearer"
	keyToken     = "auth_token"
)

var (
	errNoAuthorizationHeader  = errors.New("Authorization header is not set")
	errBadAuthorizationHeader = errors.New("Invalid authorization header is not set")
	errInvalidJwtToken        = errors.New("The token isn't valid")
)

var (
	// default random secret key used to validate JWT tokens
	secret = securecookie.GenerateRandomKey(32)
)

// Config defines options for authentication middleware.
type Config struct {
	// Validate is function to validate credentials
	Validate func(r *http.Request, username, password string) error

	// ValidateCustom is function to validate custom authorization scheme
	ValidateCustom func(r *http.Request, scheme, custom string) error

	// UnauthorizedHandler is optional error handler to override default error handler.
	UnauthorizedHandler http.Handler

	// SecretKey is function to get secret key for given JWT token
	SecretKey jwt.Keyfunc

	// ValidateToken is function to validate claims of JWT token.
	ValidateToken func(r *http.Request, token *jwt.Token) error
}

func (config Config) setDefaults() Config {
	if config.UnauthorizedHandler == nil {
		config.UnauthorizedHandler = http.HandlerFunc(defaultUnauthorizedHandler)
	}
	if config.SecretKey == nil {
		config.SecretKey = defaultSecretKey
	}
	return config
}

func defaultSecretKey(token *jwt.Token) (interface{}, error) {
	return []byte(secret), nil
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

// GetToken returns auth token for given request context
func GetToken(r *http.Request) *jwt.Token {
	var i = context.Get(r, keyToken)
	if i == nil {
		return nil
	}
	return i.(*jwt.Token)
}

// gohttp middleware
type gohttpMiddleware struct {
	config Config
	next   http.Handler
}

// ServeHTTP implementation.
func (m *gohttpMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var err = m.config.validate(r)
	if err == nil {
		m.next.ServeHTTP(w, r)
	} else {
		// TODO log error
		m.config.UnauthorizedHandler.ServeHTTP(w, r)
	}
}

// Validates auth header or auth_token.
func (config Config) validate(r *http.Request) error {
	var h = r.Header.Get("Authorization")
	if len(h) > 0 {
		return config.validateHeader(r, h)
	}
	if r.Method == "GET" {
		var token = r.FormValue(keyToken)
		if len(token) > 0 {
			return config.validateJWT(r, token)
		}
	}
	return errNoAuthorizationHeader
}

// Validates authorization header.
func (config Config) validateHeader(r *http.Request, auth string) error {
	if len(auth) == 0 {
		return errNoAuthorizationHeader
	}

	var f = strings.Fields(auth)
	if len(f) != 2 {
		return errBadAuthorizationHeader
	}

	var scheme = strings.ToLower(f[0])
	var token = f[1]

	switch scheme {
	case schemeBasic:
		return config.validateBasic(r, token)
	case schemeBearer:
		return config.validateJWT(r, token)
	default:
		if config.ValidateCustom != nil {
			return config.ValidateCustom(r, scheme, token)
		}
		// TODO support annonymous/guest mode
		return nil
	}
}

func (config Config) validateBasic(r *http.Request, token string) error {
	var str, err = base64.StdEncoding.DecodeString(token)
	if err != nil {
		return err
	}
	var creds = bytes.SplitN(str, []byte(":"), 2)
	return config.Validate(r, string(creds[0]), string(creds[1]))
}

func (config Config) validateJWT(r *http.Request, token string) error {
	var tok, err = jwt.Parse(token, config.SecretKey)
	if err != nil {
		return err
	}

	if !tok.Valid {
		return errInvalidJwtToken
	}

	if config.ValidateToken != nil {
		return config.ValidateToken(r, tok)
	}

	context.Set(r, keyToken, tok)

	return nil
}

// defaultUnauthorizedHandler provides a default HTTP 401 Unauthorized response.
func defaultUnauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}
