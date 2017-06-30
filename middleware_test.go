package auth

import (
	"fmt"
	"github.com/go-chi/chi"
	"github.com/stretchr/testify/assert"
	"gopkg.in/gavv/httpexpect.v1"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBasicAuthNoCredentials(t *testing.T) {
	config := makeTestConfig()
	c := makectx(t, config, middlewareServer(config))
	c.expect.GET("/private").Expect().Status(http.StatusUnauthorized)
}

func TestBasicAuthValidCredentials(t *testing.T) {
	config := makeTestConfig()
	c := makectx(t, config, middlewareServer(config))
	c.expect.GET("/private").WithBasicAuth("bob", "b0b").Expect().Status(http.StatusOK)
}

func TestValidJWT(t *testing.T) {
	config := makeTestConfig()
	c := makectx(t, config, middlewareServer(config))
	token := c.makeToken("bob", "b0b")

	c.expect.GET("/private").
		WithHeader(authorizationHeader, fmt.Sprintf("%s %s", schemeBearer, token)).
		Expect().
		Status(http.StatusOK)

	c.expect.GET("/private").
		WithQuery(defaultTokenKey, token).
		Expect().
		Status(http.StatusOK)
}

type C struct {
	*testing.T
	config *Config
	server *httptest.Server
	expect *httpexpect.Expect
}

func (c *C) makeToken(username, password string) string {
	user, err := c.config.UserStore.ValidateCredentials(username, password)
	assert.Nil(c, err)
	assert.NotNil(c, user)
	issuedAt := now()
	token := &Token{
		UserID:    user.GetID(),
		UserName:  user.GetName(),
		IssuedAt:  Timestamp(issuedAt),
		ExpiredAt: Timestamp(issuedAt.Add(c.config.TokenExpiration)),
	}
	result, err := token.Encode(c.config)
	assert.Nil(c, err)
	assert.NotEmpty(c, result)
	return result
}

func makectx(t *testing.T, config *Config, server *httptest.Server) *C {
	return &C{
		T:      t,
		config: config,
		server: server,
		expect: httpexpect.WithConfig(httpexpect.Config{
			BaseURL:  server.URL,
			Reporter: httpexpect.NewAssertReporter(t),
			Printers: []httpexpect.Printer{
				httpexpect.NewDebugPrinter(t, true),
			},
		}),
	}
}

func middlewareServer(config *Config) *httptest.Server {
	r := chi.NewRouter()

	r.Use(RequireUser(config))

	r.Get("/private", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	return httptest.NewServer(r)
}
