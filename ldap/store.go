package ldap

import (
	"fmt"
	ldapclient "github.com/gocontrib/go-ldap-client"
)

type UserInfo struct {
	ID         string
	Name       string
	Email      string
	Attributes map[string]string
}

type UserStore struct {
	pool            Pool
	displayNameAttr string
	emailAttr       string
	config          Config
}

func NewUserStore(pool Pool, config Config) *UserStore {
	displayNameAttr := config.DisplayNameAttr
	if len(displayNameAttr) == 0 {
		displayNameAttr = "displayName"
	}
	emailAttr := config.EmailAttr
	if len(emailAttr) == 0 {
		emailAttr = "mail"
	}
	return &UserStore{
		pool:            pool,
		displayNameAttr: displayNameAttr,
		emailAttr:       emailAttr,
		config:          config,
	}
}

func (us *UserStore) ValidateCredentials(username, password string) (*UserInfo, error) {
	client, err := us.pool.Get()
	if err != nil {
		return nil, err
	}
	defer us.pool.Put(client)
	ok, attrs, err := client.Authenticate(username, password)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("ldap auth failed for user '%s'", username)
	}
	return us.makeUser(client, username, attrs)
}

func (us *UserStore) FindUserByID(userID string) (*UserInfo, error) {
	client, err := us.pool.Get()
	if err != nil {
		return nil, err
	}
	defer us.pool.Put(client)
	attrs, err := client.FindUser(userID)
	if err != nil {
		return nil, err
	}
	return us.makeUser(client, userID, attrs)
}

func (us *UserStore) Close() {
	if us.pool != nil {
		us.pool.Close()
		us.pool = nil
	}
}

func (us *UserStore) makeUser(client *ldapclient.LDAPClient, id string, attrs map[string]string) (*UserInfo, error) {
	var err error
	displayName, _ := attrs[us.displayNameAttr]
	email, _ := attrs[us.emailAttr]

	if us.config.GetMoreUserInfo != nil {
		var extra map[string]string
		extra, err = us.config.GetMoreUserInfo(client, attrs)
		if extra != nil {
			for k, v := range extra {
				attrs[k] = v
			}
		}
	}

	return &UserInfo{
		ID:         id,
		Name:       displayName,
		Email:      email,
		Attributes: attrs,
	}, err
}
