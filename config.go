package auth

import (
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gocontrib/parse"
	"github.com/gorilla/securecookie"
)

const (
	defaultTokenKey    = "token"
	defaultTokenCookie = "jwt_token"
)

var (
	defaultSingingMethod = jwt.SigningMethodHS256
	defaultSecretKey     = securecookie.GenerateRandomKey(32)
)

// Config defines options for authentication middleware.
type Config struct {
	// UserStore to validate credentials
	UserStore   UserStore
	UserStoreEx UserStoreEx

	// TokenKey specifies name of token field to extract from query string
	TokenKey string

	// TokenCookie specifies cookie name to extract from cookies
	TokenCookie string

	// SingingMethod specifies JWT signing method
	SingingMethod jwt.SigningMethod

	// SecretKey is key string or function to get secret key for given JWT token
	SecretKey interface{}

	TokenExpiration time.Duration
}

// Initializes default handlers if they omitted.
func (c *Config) SetDefaults() *Config {
	if len(c.TokenKey) == 0 {
		c.TokenKey = defaultTokenKey
	}
	if len(c.TokenCookie) == 0 {
		c.TokenCookie = defaultTokenCookie
	}
	if c.SingingMethod == nil {
		c.SingingMethod = defaultSingingMethod
	}
	if c.SecretKey == nil {
		s := os.Getenv("JWT_SECRET")
		if len(s) > 0 {
			c.SecretKey = []byte(s)
		} else {
			c.SecretKey = defaultSecretKey
		}
	}
	if c.TokenExpiration.Nanoseconds() == 0 {
		c.TokenExpiration = parse.MustDuration("7d")
	}
	return c
}
