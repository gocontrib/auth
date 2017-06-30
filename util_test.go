package auth

import (
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestGetString(t *testing.T) {
	m := make(map[string]interface{})
	v := getString(m, "key")
	assert.Empty(t, v)

	m = make(map[string]interface{})
	m["key"] = "value"
	v = getString(m, "key")
	assert.Equal(t, "value", v)

	m = make(map[string]interface{})
	m["key"] = Token{}
	v = getString(m, "key")
	assert.Empty(t, v)
}

func TestGetTime(t *testing.T) {
	testOK := func(value interface{}) {
		m := make(map[string]interface{})
		m["exp"] = value
		v := getTime(m, "exp")
		assert.NotNil(t, v)
	}
	testOK(time.Now())
	now := time.Now().Unix()
	testOK(now)
	testOK(float64(now))
	testOK(fmt.Sprintf("%d", now))
	testOK(json.Number(fmt.Sprintf("%d", now)))

	m := make(map[string]interface{})
	v := getTime(m, "exp")
	assert.Nil(t, v)

	m = make(map[string]interface{})
	m["exp"] = "abc"
	v = getTime(m, "exp")
	assert.Nil(t, v)

	m = make(map[string]interface{})
	m["exp"] = &Token{}
	v = getTime(m, "exp")
	assert.Nil(t, v)
}
