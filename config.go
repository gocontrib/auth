package auth

import (
	"context"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/securecookie"
	"net/http"
)

const defaultTokenKey = "auth_token"

var defaultSingingMethod = jwt.SigningMethodHS256
var defaultSecretKey = securecookie.GenerateRandomKey(32)

// Config defines options for authentication middleware.
type Config struct {
	// ValidateUser is function to validate user credentials
	ValidateUser func(r *http.Request, username, password string) (string, error)

	// ValidateToken is function to validate token.
	ValidateToken func(r *http.Request, token *Token) error

	// ValidateCustom is function to validate custom authorization scheme
	ValidateCustom func(r *http.Request, scheme, custom string) (context.Context, error)

	// ErrorHandler is optional error handler to override default error handler.
	ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

	// TokenKey specifies name of token field to extract from query string
	TokenKey string

	SingingMethod jwt.SigningMethod

	// SecretKey is key string or function to get secret key for given JWT token
	SecretKey interface{}
}

// Initializes default handlers if they omitted.
func (c *Config) setDefaults() *Config {
	if len(c.TokenKey) == 0 {
		c.TokenKey = defaultTokenKey
	}
	if c.SingingMethod == nil {
		c.SingingMethod = defaultSingingMethod
	}
	if c.SecretKey == nil {
		c.SecretKey = defaultSecretKey
	}
	if c.ErrorHandler == nil {
		c.ErrorHandler = defaultErrorHandler
	}
	return c
}

// defaultErrorHandler provides a default HTTP 401 Unauthorized response.
func defaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	var text = http.StatusText(http.StatusUnauthorized)
	if err != nil {
		text += ": " + err.Error()
	}
	http.Error(w, text, http.StatusUnauthorized)
}
