package auth

import (
	"github.com/gocontrib/auth/ldap"
)

func NewLdapStore(config ldap.Config) UserStore {
	pool := ldap.NewPool(config)
	store := ldap.NewUserStore(pool, config)
	return &ldapStore{store}
}

type ldapStore struct {
	store *ldap.UserStore
}

func (us *ldapStore) ValidateCredentials(username, password string) (User, error) {
	u, err := us.store.ValidateCredentials(username, password)
	if err != nil {
		return nil, err
	}
	return us.makeUser(u), nil
}

func (us *ldapStore) FindUserByID(userID string) (User, error) {
	u, err := us.store.FindUserByID(userID)
	if err != nil {
		return nil, err
	}
	return us.makeUser(u), nil
}

func (us *ldapStore) makeUser(info *ldap.UserInfo) User {
	return &ldapUser{
		ID:    info.ID,
		Name:  info.Name,
		Email: info.Email,
	}
}

func (us *ldapStore) Close() {
	us.store.Close()
}

type ldapUser struct {
	ID    string
	Name  string
	Email string
}

func (u *ldapUser) GetID() string {
	return u.ID
}

func (u *ldapUser) GetName() string {
	return u.Name
}

func (u *ldapUser) GetEmail() string {
	return u.Email
}

func (u *ldapUser) IsAdmin() bool {
	return false
}
