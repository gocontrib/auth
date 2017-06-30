package auth

import (
	"fmt"
	"strconv"
	"time"
)

type Timestamp time.Time

func (t Timestamp) Unix() int64 {
	return time.Time(t).Unix()
}

func (t Timestamp) MarshalJSON() ([]byte, error) {
	ts := time.Time(t).Unix()
	stamp := fmt.Sprint(ts)
	return []byte(stamp), nil
}

func (t *Timestamp) UnmarshalJSON(b []byte) error {
	ts, err := strconv.ParseInt(string(b), 10, 32)
	if err != nil {
		return err
	}
	*t = Timestamp(time.Unix(ts, 0))
	return nil
}
