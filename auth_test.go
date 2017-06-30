package auth

import (
	. "github.com/franela/go-supertest"
	"github.com/gohttp/app"
	"net/http/httptest"
	"net/http"
	"testing"
	"fmt"
	"encoding/base64"
)

func TestBasicAuthNoCredentials(t *testing.T) {
	s := gohttpServer(nil)

	NewRequest(s.URL).
		Get("/private").
		Expect(http.StatusUnauthorized)
}

func TestBasicAuthValidCredentials(t *testing.T) {
	var validateCalled = false
	var validationResult interface{}

	s := gohttpServer(func(valid bool) {
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

func gohttpServer(cb func(bool)) *httptest.Server {
	a := app.New()

	a.Use(Middleware(&Config{
		ValidateUser: func(r *http.Request, user, password string) (string, error) {
			res := user == "bob" && password == "b0b"
			if cb != nil {
				cb(res)
			}
			if res {
				return "", nil
			}
			return "", fmt.Errorf("Invalid user name %s or password", user)
		},
	}))

	a.Get("/private", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	return httptest.NewServer(a)
}
