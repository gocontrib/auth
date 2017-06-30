package auth

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func defaultConfig() *Config {
	return (&Config{}).setDefaults()
}

func TestParseValidToken(t *testing.T) {
	config := defaultConfig()
	token := &Token{
		UserID:    "test",
		UserName:  "test",
		IssuedAt:  Timestamp(now()),
		ExpiredAt: Timestamp(now().Add(time.Hour)),
		ClientIP:  "127.0.0.1",
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
