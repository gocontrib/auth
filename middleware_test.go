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

func TestBasicAuth_NoCredentials(t *testing.T) {
	config := makeTestConfig()
	c := makectx(t, config, middlewareServer(config))
	c.expect.GET("/data").Expect().Status(http.StatusUnauthorized)
	c.expect.GET("/admin/data").Expect().Status(http.StatusUnauthorized)
}

func TestBasicAuth_ValidCredentials(t *testing.T) {
	config := makeTestConfig()
	c := makectx(t, config, middlewareServer(config))
	c.expect.GET("/data").WithBasicAuth("bob", "b0b").Expect().Status(http.StatusOK)
	c.expect.GET("/data").WithBasicAuth("admin", "admin").Expect().Status(http.StatusOK)
	c.expect.GET("/admin/data").WithBasicAuth("admin", "admin").Expect().Status(http.StatusOK)
}

func TestBasicAuth_NoAdminPrivileges(t *testing.T) {
	config := makeTestConfig()
	c := makectx(t, config, middlewareServer(config))
	c.expect.GET("/admin/data").WithBasicAuth("bob", "b0b").Expect().Status(http.StatusUnauthorized)
}

func TestJWT_Valid(t *testing.T) {
	testJWT(t, "/data", "bob", "b0b", http.StatusOK)
}

func TestJWT_ValidAdmin(t *testing.T) {
	testJWT(t, "/admin/data", "admin", "admin", http.StatusOK)
}

func TestJWT_NoAdminPrivileges(t *testing.T) {
	testJWT(t, "/admin/data", "bob", "b0b", http.StatusUnauthorized)
}

func testJWT(t *testing.T, path, username, pwd string, status int) {
	config := makeTestConfig()
	c := makectx(t, config, middlewareServer(config))
	token := c.makeToken(username, pwd)

	c.expect.GET(path).
		WithHeader(authorizationHeader, fmt.Sprintf("%s %s", schemeBearer, token)).
		Expect().
		Status(status)

	c.expect.GET(path).
		WithQuery(defaultTokenKey, token).
		Expect().
		Status(status)
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

	emptyHandler := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	}

	r.Get("/data", emptyHandler)

	ar := chi.NewRouter()
	ar.Use(RequireAdmin(config))
	ar.Get("/data", emptyHandler)

	r.Mount("/admin", ar)

	return httptest.NewServer(r)
}
