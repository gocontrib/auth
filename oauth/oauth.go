package oauth

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gocontrib/auth"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/facebook"
)

// TODO support more providers
func init() {
	providers := filterNilProviders([]goth.Provider{
		makeProvider("facebook"),
	})
	goth.UseProviders(providers...)
}

func filterNilProviders(in []goth.Provider) []goth.Provider {
	var out []goth.Provider
	for _, v := range in {
		if v != nil {
			out = append(out, v)
		}
	}
	return out
}

func makeProvider(provider string) goth.Provider {
	// TODO get host from config
	host := "http://localhost:4201"
	callback := host + "/api/oauth/callback/" + provider
	p := strings.ToUpper(provider)
	key := os.Getenv(p + "_KEY")
	secret := os.Getenv(p + "_SECRET")
	if len(key) == 0 || len(secret) == 0 {
		return nil
	}

	switch provider {
	case "facebook":
		return facebook.New(key, secret, callback)
	}
	panic("invalid provider")
}

type Router interface {
	Get(pattern string, h http.HandlerFunc)
}

func RegisterAPI(mux Router, config *auth.Config) {
	userStore := config.UserStoreEx
	if userStore == nil {
		return
	}

	mux.Get("/api/oauth/login/:provider", func(w http.ResponseWriter, r *http.Request) {
		// try to get the user without re-authenticating
		if user, err := gothic.CompleteUserAuth(w, r); err == nil {
			completeOAuthFlow(w, r, config, user)
		} else {
			gothic.BeginAuthHandler(w, r)
		}
	})

	mux.Get("/api/oauth/logout/:provider", func(w http.ResponseWriter, r *http.Request) {
		gothic.Logout(w, r)
		w.Header().Set("Location", "/")
		w.WriteHeader(http.StatusTemporaryRedirect)
	})

	mux.Get("/api/oauth/callback/:provider", func(w http.ResponseWriter, r *http.Request) {
		user, err := gothic.CompleteUserAuth(w, r)
		if err != nil {
			fmt.Fprintln(w, err)
			return
		}
		completeOAuthFlow(w, r, config, user)
	})
}

func completeOAuthFlow(w http.ResponseWriter, r *http.Request, config *auth.Config, account goth.User) {
	ctx := r.Context()
	userStore := config.UserStoreEx
	if userStore == nil {
		return
	}

	user, err := userStore.FindUserByEmail(ctx, account.Email)
	if err != nil {
		user, err = userStore.CreateUser(ctx, account)
		if err != nil {
			fmt.Fprintln(w, err)
			return
		}
	}

	// TODO link external account to the user

	auth.WriteLoginResponse(w, r, config, user)
}
