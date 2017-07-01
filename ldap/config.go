package ldap

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
}
