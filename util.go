package auth

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/tomasen/realip"
)

const contentJSON = "application/json"

var now = func() time.Time {
	return time.Now().UTC()
}

var getIssuer = func() string {
	hostname, _ := os.Hostname()
	return hostname
}

var getClientIP = func(r *http.Request) string {
	return realip.RealIP(r)
}

func getString(data map[string]interface{}, key string) string {
	v, ok := data[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

func getTime(data map[string]interface{}, key string) *time.Time {
	value, ok := data[key]
	if !ok {
		return nil
	}
	switch v := value.(type) {
	case time.Time:
		return &v
	case float64:
		t := time.Unix(int64(v), 0).UTC()
		return &t
	case int64:
		t := time.Unix(v, 0).UTC()
		return &t
	case json.Number:
		i, _ := v.Int64()
		t := time.Unix(i, 0).UTC()
		return &t
	case string:
		i, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			return nil
		}
		t := time.Unix(i, 0).UTC()
		return &t
	default:
		return nil
	}
}

func sendJSON(w http.ResponseWriter, result interface{}) {
	w.Header().Set("Content-Type", contentJSON)

	marshaller, ok := result.(json.Marshaler)
	if ok {
		b, err := marshaller.MarshalJSON()
		if err != nil {
			// TODO check whether it is possible to send error at this phase
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		w.Write(b)
		return
	}

	err := json.NewEncoder(w).Encode(result)
	if err != nil {
		// TODO check whether it is possible to send error at this phase
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func sendError(w http.ResponseWriter, err error, status int) {
	// TODO consider to send error as JSON
	http.Error(w, err.Error(), status)
}
