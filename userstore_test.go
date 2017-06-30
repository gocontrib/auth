package auth

import "errors"

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
