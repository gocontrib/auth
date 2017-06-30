package auth

import (
	"encoding/base64"
	"fmt"
	. "github.com/franela/go-supertest"
	"github.com/gohttp/app"
	"github.com/kataras/go-errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBasicAuthNoCredentials(t *testing.T) {
	s := gohttpServer()

	NewRequest(s.URL).
		Get("/private").
		Expect(http.StatusUnauthorized)
}

func TestBasicAuthValidCredentials(t *testing.T) {
	s := gohttpServer()

	NewRequest(s.URL).
		Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("bob:b0b"))).
		Get("/private").
		Expect(http.StatusOK, "ok")
}

func gohttpServer() *httptest.Server {
	a := app.New()

	store := testUserStore{
		"bob": &testUser{
			ID:  "bob",
			Pwd: "b0b",
		},
	}

	a.Use(RequireUser(&Config{
		UserStore: store,
	}))

	a.Get("/private", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	return httptest.NewServer(a)
}

type testUser struct {
	ID    string
	Email string
	Pwd   string
	Admin bool
}

func (u *testUser) GetID() string {
	return u.ID
}

func (u *testUser) GetEmail() string {
	return u.Email
}

func (u *testUser) IsAdmin() bool {
	return u.Admin
}

type testUserStore map[string]*testUser

func (us testUserStore) ValidateCredentials(username, password string) (User, error) {
	u, ok := us[username]
	if !ok {
		return nil, errors.New("user not found")
	}
	if u.Pwd != password {
		return nil, errors.New("invalid password")
	}
	return u, nil
}

func (us testUserStore) FindUserByID(userID string) (User, error) {
	for _, u := range us {
		if u.ID == userID {
			return u, nil
		}
	}
	return nil, errors.New("user not found")
}
