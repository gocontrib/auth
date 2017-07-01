package auth

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/gocontrib/parse"
	"github.com/gorilla/securecookie"
	"time"
)

const defaultTokenKey = "auth_token"

var defaultSingingMethod = jwt.SigningMethodHS256
var defaultSecretKey = securecookie.GenerateRandomKey(32)

// Config defines options for authentication middleware.
type Config struct {
	// UserStore to validate credentials
	UserStore UserStore

	// TokenKey specifies name of token field to extract from query string
	TokenKey string

	// SingingMethod specifies JWT signing method
	SingingMethod jwt.SigningMethod

	// SecretKey is key string or function to get secret key for given JWT token
	SecretKey interface{}

	TokenExpiration time.Duration
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
	if c.TokenExpiration.Nanoseconds() == 0 {
		c.TokenExpiration = parse.MustDuration("7d")
	}
	return c
}
