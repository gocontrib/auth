package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func defaultConfig() *Config {
	return (&Config{}).SetDefaults()
}

func TestParseValidToken(t *testing.T) {
	config := defaultConfig()
	token := &Token{
		UserID:    "test",
		UserName:  "test",
		IssuedAt:  Timestamp(now()),
		ExpiredAt: Timestamp(now().Add(time.Hour)),
		ClientIP:  "127.0.0.1",
		Claims: map[string]interface{}{
			"role": "admin",
		},
	}
	str, err := token.Encode(config)
	assert.Nil(t, err)
	assert.NotEmpty(t, str)

	token2, err := parseToken(config, str, token.ClientIP, false)
	assert.Nil(t, err)
	assert.NotNil(t, token2)
	assert.Equal(t, token.UserID, token2.UserID)
	assert.Equal(t, token.UserName, token2.UserName)
}
