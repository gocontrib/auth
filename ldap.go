package auth

import (
	"context"

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

func (us *ldapStore) ValidateCredentials(ctx context.Context, username, password string) (User, error) {
	u, err := us.store.ValidateCredentials(username, password)
	if err != nil {
		return nil, err
	}
	return us.makeUser(u), nil
}

func (us *ldapStore) FindUserByID(ctx context.Context, userID string) (User, error) {
	u, err := us.store.FindUserByID(userID)
	if err != nil {
		return nil, err
	}
	return us.makeUser(u), nil
}

func (us *ldapStore) makeUser(info *ldap.UserInfo) User {
	// TODO determine user role
	return &StdUser{
		ID:    info.ID,
		Name:  info.Name,
		Email: info.Email,
	}
}

func (us *ldapStore) Close() {
	us.store.Close()
}
