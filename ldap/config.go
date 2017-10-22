package ldap

import (
	ldapclient "github.com/gocontrib/go-ldap-client"
)

type Config struct {
	Base               string
	Host               string
	ServerName         string
	Port               int
	BindDN             string
	BindPassword       string
	UserFilter         string
	GroupFilter        string
	Attributes         []string
	InsecureSkipVerify bool
	DisplayNameAttr    string
	EmailAttr          string
	PoolCapacity       int
	GetMoreUserInfo    func(client *ldapclient.LDAPClient, attrs map[string]string) (map[string]string, error)
}
