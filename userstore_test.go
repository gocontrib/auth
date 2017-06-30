package auth

import (
	"errors"
	"fmt"
	"github.com/satori/go.uuid"
)

func makeTestUserStore() testUserStore {
	store := testUserStore{
		"bob": &testUser{
			Pwd: "b0b",
		},
		"rob": &testUser{
			Pwd: "r0b",
		},
		"joe": &testUser{
			Pwd: "j0e",
		},
	}
	store.init()
	return store
}

type testUserStore map[string]*testUser

func (us testUserStore) init() {
	for k, u := range us {
		if len(u.ID) == 0 {
			u.ID = uuid.NewV4().String()
		}
		if len(u.Name) == 0 {
			u.Name = k
		}
		if len(u.Email) == 0 {
			u.Email = fmt.Sprintf("%s@test.net", k)
		}
	}
}

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

type testUser struct {
	ID    string
	Name  string
	Email string
	Pwd   string
	Admin bool
}

func (u *testUser) GetID() string {
	return u.ID
}

func (u *testUser) GetName() string {
	return u.Name
}

func (u *testUser) GetEmail() string {
	return u.Email
}

func (u *testUser) IsAdmin() bool {
	return u.Admin
}
