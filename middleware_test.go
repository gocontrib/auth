package auth

import (
	"fmt"
	"github.com/go-chi/chi"
	"gopkg.in/gavv/httpexpect.v1"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBasicAuthNoCredentials(t *testing.T) {
	c := makectx(t, middlewareServer())
	c.expect.GET("/private").Expect().Status(http.StatusUnauthorized)
}

func TestBasicAuthValidCredentials(t *testing.T) {
	c := makectx(t, middlewareServer())
	c.expect.GET("/private").WithBasicAuth("bob", "b0b").Expect().Status(http.StatusOK)
}

type C struct {
	*testing.T
	server *httptest.Server
	expect *httpexpect.Expect
}

func makectx(t *testing.T, server *httptest.Server) *C {
	return &C{
		// t: t,
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

func middlewareServer() *httptest.Server {
	a := chi.NewRouter()

	store := testUserStore{
		"bob": &testUser{
			ID:  "bob",
			Pwd: "b0b",
		},
	}

	a.Use(RequireUser(&Config{
		UserStore: store,
	}))

	a.Get("/private", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	return httptest.NewServer(a)
}
