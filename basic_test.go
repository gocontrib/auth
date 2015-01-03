package auth

import . "github.com/franela/go-supertest"
import "github.com/gohttp/app"
import "net/http/httptest"
import "net/http"
import "testing"
import "fmt"
import "encoding/base64"

func TestBasicAuthNoCredentials(t *testing.T) {
	s := newServer(nil)

	NewRequest(s.URL).
		Get("/private").
		Expect(http.StatusUnauthorized)
}

func TestBasicAuthValidCredentials(t *testing.T) {
	var validateCalled = false
	var validationResult interface{} = nil

	s := newServer(func(valid bool) {
		validateCalled = true
		validationResult = valid
	})

	NewRequest(s.URL).
		Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("bob:b0b"))).
		Get("/private").
		Expect(http.StatusOK, "ok")

	if !validateCalled {
		t.Fail()
	}
}

func newServer(cb func(bool)) *httptest.Server {
	a := app.New()

	a.Use(Basic(BasicConfig{
		Validate: func(r *http.Request, user, password string) bool {
			res := user == "bob" && password == "b0b"
			if cb != nil {
				cb(res)
			}
			return res
		},
	}))

	a.Get("/private", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	return httptest.NewServer(a)
}
