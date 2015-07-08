package auth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/drone/config"
	"github.com/gocontrib/context"
	"github.com/gocontrib/request"
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
	errJwtNoUserID            = errors.New("JWT has no user_id claim")
)

var (
	// random key used to create jwt if none provided in the configuration
	random  = securecookie.GenerateRandomKey(32)
	secret  = config.String("session-secret", string(random))
	expires = config.Duration("session-expires", time.Hour*24*30)
)

// GenerateToken generates a JWT token for the user session
// that can be appended to the #access_token segment to
// facilitate client-based OAuth2.
func GenerateToken(r *http.Request, userID interface{}) (string, error) {
	var token = jwt.New(jwt.GetSigningMethod("HS256"))
	token.Claims["user_id"] = userID
	token.Claims["audience"] = request.GetURL(r)
	token.Claims["expires"] = time.Now().UTC().Add(*expires).Unix()
	return token.SignedString([]byte(*secret))
}

// Config defines options for authentication middleware.
type Config struct {
	// Validate is function to validate credentials
	Validate func(r *http.Request, username, password string) error

	// ValidateCustom is function to validate custom authorization scheme
	ValidateCustom func(r *http.Request, scheme, custom string) error

	// ErrorHandler is optional error handler to override default error handler.
	ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

	// SecretKey is key string or function to get secret key for given JWT token
	SecretKey interface{}
	key       jwt.Keyfunc

	// ValidateToken is function to validate claims of JWT token.
	ValidateToken func(r *http.Request, token *jwt.Token) error

	// ValidateUser is function to validate user by id
	ValidateUser func(r *http.Request, uid int64) error
}

// Initializes default handlers if they omitted.
func (config Config) setDefaults() Config {
	if config.ErrorHandler == nil {
		config.ErrorHandler = defaultErrorHandler
	}
	if config.SecretKey == nil {
		config.SecretKey = defaultSecretKey
	}
	config.key = keyFn(config.SecretKey)
	return config
}

// Default JWT key function.
func keyFn(i interface{}) jwt.Keyfunc {
	switch i.(type) {
	case jwt.Keyfunc:
		return i.(jwt.Keyfunc)
	case func(*jwt.Token) (interface{}, error):
		return i.(func(*jwt.Token) (interface{}, error))
	case string:
		var s = i.(string)
		return func(_ *jwt.Token) (interface{}, error) {
			return []byte(s), nil
		}
	case []byte:
		var s = i.([]byte)
		return func(_ *jwt.Token) (interface{}, error) {
			return s, nil
		}
	default:
		panic("invalid secret key")
	}
}

func defaultSecretKey(token *jwt.Token) (interface{}, error) {
	return []byte(*secret), nil
}

// Middleware returns gohttp auth middleware.
func Middleware(config Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return Handler(config, next)
	}
}

// Handler creates auth middleware http handler.
func Handler(config Config, next http.Handler) http.Handler {
	return &middleware{config.setDefaults(), next}
}

// GetToken returns auth token for given request context
// TODO consider to remove from this package to remove dependency on gorilla/context package.
func GetToken(r *http.Request) *jwt.Token {
	var i = context.Get(r, keyToken)
	if i == nil {
		return nil
	}
	return i.(*jwt.Token)
}

// gohttp middleware
type middleware struct {
	config Config
	next   http.Handler
}

// ServeHTTP implementation.
func (m *middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var err = m.config.validate(r)
	if err == nil {
		m.next.ServeHTTP(w, r)
	} else {
		m.config.ErrorHandler(w, r, err)
	}
}

// Validates auth header or auth_token.
func (config Config) validate(r *http.Request) error {
	var h = r.Header.Get("Authorization")
	if len(h) > 0 {
		return config.validateHeader(r, h)
	}

	// auth_token as part of url
	if r.Method == "GET" {
		var token = r.URL.Query().Get(keyToken)
		if len(token) > 0 {
			return config.validateJWT(r, token)
		}
	}

	// auth_token as part of form
	var token = r.FormValue(keyToken)
	if len(token) > 0 {
		return config.validateJWT(r, token)
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
	var tok, err = jwt.Parse(token, config.key)
	if err != nil {
		return err
	}

	if !tok.Valid {
		return errInvalidJwtToken
	}

	if config.ValidateToken != nil {
		err = config.ValidateToken(r, tok)
	}

	if config.ValidateUser != nil {
		var uid, ok = tok.Claims["user_id"].(float64)
		if !ok {
			return errJwtNoUserID
		}
		err = config.ValidateUser(r, int64(uid))
	}

	if err != nil {
		context.Set(r, keyToken, tok)
	}

	return err
}

// defaultErrorHandler provides a default HTTP 401 Unauthorized response.
func defaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	var text = http.StatusText(http.StatusUnauthorized)
	if err != nil {
		text += ": " + err.Error()
	}
	http.Error(w, text, http.StatusUnauthorized)
}
