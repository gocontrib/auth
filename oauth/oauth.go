package oauth

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi"
	"github.com/gocontrib/auth"
	"github.com/gocontrib/log"
	"github.com/gocontrib/request"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/facebook"
	"github.com/markbates/goth/providers/vk"
)

// TODO support more providers
func initProviders(config *auth.Config) {
	providers := filterNilProviders([]goth.Provider{
		makeProvider(config, "facebook"),
		makeProvider(config, "vk"),
	})
	if len(providers) > 0 {
		goth.UseProviders(providers...)
	} else {
		log.Warning("no oauth providers")
	}
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

func makeProvider(config *auth.Config, provider string) goth.Provider {
	p := strings.ToUpper(provider)
	key := os.Getenv(p + "_KEY")
	secret := os.Getenv(p + "_SECRET")
	if len(key) == 0 || len(secret) == 0 {
		log.Warning("%s has no keys\n", provider)
		return nil
	}

	baseURL := strings.TrimRight(getBaseURL(config), "/")
	callbackURL := baseURL + "/api/oauth/callback/" + provider
	log.Debug("%s callback: %s\n", provider, callbackURL)

	switch provider {
	case "facebook":
		return facebook.New(key, secret, callbackURL)
	case "vk":
		return vk.New(key, secret, callbackURL)
	}
	panic("invalid provider")
}

func getBaseURL(config *auth.Config) string {
	if len(config.ServerURL) > 0 {
		return config.ServerURL
	}
	if config.ServerPort != 0 {
		return fmt.Sprintf("http://localhost:%d", config.ServerPort)
	}
	hostname, err := os.Hostname()
	if err == nil {
		return fmt.Sprintf("http://%s", hostname)
	}
	return "http://localhost:4200"
}

type Router interface {
	Get(pattern string, h http.HandlerFunc)
}

func RegisterAPI(mux Router, config *auth.Config) {
	config = config.SetDefaults()

	userStore := config.UserStoreEx
	if userStore == nil {
		return
	}

	initProviders(config)

	defaultGetProviderName := gothic.GetProviderName
	gothic.GetProviderName = func(r *http.Request) (string, error) {
		providerName := chi.URLParam(r, "provider")
		if len(providerName) > 0 {
			return providerName, nil
		}
		return defaultGetProviderName(r)
	}

	mux.Get("/api/oauth/login/{provider}", func(w http.ResponseWriter, r *http.Request) {
		// try to get the user without re-authenticating
		if user, err := gothic.CompleteUserAuth(w, r); err == nil {
			completeOAuthFlow(w, r, config, user)
		} else {
			gothic.BeginAuthHandler(w, r)
		}
	})

	mux.Get("/api/oauth/logout/{provider}", func(w http.ResponseWriter, r *http.Request) {
		gothic.Logout(w, r)
		w.Header().Set("Location", "/")
		w.WriteHeader(http.StatusTemporaryRedirect)
	})

	mux.Get("/api/oauth/callback/{provider}", func(w http.ResponseWriter, r *http.Request) {
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
		// create user and link with external account
		user, err = userStore.CreateUser(ctx, account)
		if err != nil {
			fmt.Fprintln(w, err)
			return
		}
	}

	token := auth.MakeToken(r, config, user)
	tokenString, err3 := token.Encode(config)
	if err3 != nil {
		auth.SendError(w, err3)
		return
	}

	request.SetCookie(w, r, config.TokenCookie, tokenString)

	// TODO support return_url, absolute url if needed
	http.Redirect(w, r, "/", http.StatusFound)
}
