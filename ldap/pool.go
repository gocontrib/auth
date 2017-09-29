package ldap

import (
	"errors"
	"sync"

	ldapclient "github.com/gocontrib/go-ldap-client"
	"gopkg.in/ldap.v2"
)

var (
	errPoolClosed = errors.New("pool is closed")
)

type Pool interface {
	Close()
	Get() (*ldapclient.LDAPClient, error)
	Put(*ldapclient.LDAPClient) error
}

func NewPool(config Config) Pool {
	capacity := config.PoolCapacity
	if capacity <= 0 {
		return &unlimitedPool{config}
	}

	return &chanPool{
		config: config,
		conns:  make(chan *ldapclient.LDAPClient, capacity),
	}
}

// based on https://github.com/fatih/pool
type chanPool struct {
	sync.Mutex
	config Config
	conns  chan *ldapclient.LDAPClient
}

func (p *chanPool) Close() {
	p.Lock()
	conns := p.conns
	p.conns = nil
	p.Unlock()

	if conns == nil {
		return
	}

	close(conns)

	for conn := range conns {
		conn.Close()
	}
}

func (p *chanPool) Get() (*ldapclient.LDAPClient, error) {
	p.Lock()
	defer p.Unlock()

	conns := p.conns
	if conns == nil {
		return nil, errPoolClosed
	}

	select {
	case conn := <-conns:
		if conn == nil {
			return nil, errPoolClosed
		}
		if isAlive(conn) {
			return conn, nil
		}
		// dead connection
		conn.Close()
		return p.NewConn()
	default:
		return p.NewConn()
	}
}

func isAlive(conn *ldapclient.LDAPClient) bool {
	if conn == nil || conn.Conn == nil {
		return false
	}
	_, err := conn.Conn.Search(&ldap.SearchRequest{
		BaseDN:     "",
		Scope:      ldap.ScopeBaseObject,
		Filter:     "(&)",
		Attributes: []string{"1.1"},
	})
	return err == nil
}

func (p *chanPool) NewConn() (*ldapclient.LDAPClient, error) {
	conn := makeClient(p.config)
	return conn, nil
}

func (p *chanPool) Put(conn *ldapclient.LDAPClient) error {
	if conn == nil {
		return errors.New("connection is nil. rejecting")
	}

	p.Lock()
	defer p.Unlock()

	if p.conns == nil {
		// pool is closed, close passed connection
		conn.Close()
		return nil
	}

	select {
	case p.conns <- conn:
		return nil
	default:
		// pool is full, close passed connection
		conn.Close()
		return nil
	}
}

type unlimitedPool struct {
	config Config
}

func (p *unlimitedPool) Close() {}

func (p *unlimitedPool) Get() (*ldapclient.LDAPClient, error) {
	return makeClient(p.config), nil
}

func (p *unlimitedPool) Put(conn *ldapclient.LDAPClient) error {
	conn.Close()
	return nil
}

func makeClient(config Config) *ldapclient.LDAPClient {
	return &ldapclient.LDAPClient{
		Base:               config.Base,
		Host:               config.Host,
		ServerName:         config.ServerName,
		Port:               config.Port,
		UseSSL:             config.Port != 389,
		BindDN:             config.BindDN,
		BindPassword:       config.BindPassword,
		UserFilter:         config.UserFilter,
		GroupFilter:        config.GroupFilter,
		Attributes:         config.Attributes,
		InsecureSkipVerify: config.InsecureSkipVerify,
	}
}
