package ldap

import (
	"fmt"
)

type UserInfo struct {
	ID    string
	Name  string
	Email string
}

type UserStore struct {
	pool            Pool
	displayNameAttr string
	emailAttr       string
}

func NewUserStore(pool Pool, config Config) *UserStore {
	displayNameAttr := config.DisplayNameAttr
	if len(displayNameAttr) == 0 {
		displayNameAttr = "displayName"
	}
	emailAttr := config.EmailAttr
	if len(emailAttr) == 0 {
		emailAttr = "email"
	}
	return &UserStore{
		pool:            pool,
		displayNameAttr: displayNameAttr,
		emailAttr:       emailAttr,
	}
}

func (us *UserStore) ValidateCredentials(username, password string) (*UserInfo, error) {
	ldapClient, err := us.pool.Get()
	if err != nil {
		return nil, err
	}
	defer us.pool.Put(ldapClient)
	ok, attrs, err := ldapClient.Authenticate(username, password)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("ldap auth failed for user '%s'", username)
	}
	return us.makeUser(username, attrs), nil
}

func (us *UserStore) FindUserByID(userID string) (*UserInfo, error) {
	ldapClient, err := us.pool.Get()
	if err != nil {
		return nil, err
	}
	defer us.pool.Put(ldapClient)
	attrs, err := ldapClient.FindUser(userID)
	if err != nil {
		return nil, err
	}
	return us.makeUser(userID, attrs), nil
}

func (us *UserStore) makeUser(id string, attrs map[string]string) *UserInfo {
	displayName, _ := attrs[us.displayNameAttr]
	email, _ := attrs[us.emailAttr]
	return &UserInfo{
		ID:    id,
		Name:  displayName,
		Email: email,
	}
}
