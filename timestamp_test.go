package auth

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestTimestamp(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	b, err := Timestamp(now).MarshalJSON()
	assert.Nil(t, err)

	ts := &Timestamp{}
	err = ts.UnmarshalJSON(b)
	assert.Nil(t, err)
	assert.Equal(t, now, time.Time(*ts))
}

func TestTimestampUnmarshalError(t *testing.T) {
	ts := &Timestamp{}
	err := ts.UnmarshalJSON([]byte("invalid"))
	assert.NotNil(t, err)
}
