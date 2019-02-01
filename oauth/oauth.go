package oauth

import (
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"

	"github.com/go-chi/chi"
	"github.com/gocontrib/auth"
	"github.com/gocontrib/log"
	"github.com/gocontrib/request"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
)

type providerFactory = func(clientKey, secret, callbackURL string, scopes ...string) goth.Provider

func WithProviders(config *auth.Config, providers ...interface{}) {
	var gothProviders []goth.Provider
	for i := 0; i+1 < len(providers); i++ {
		name := providers[i].(string)
		factory := makeProviderFactory(providers[i+1])
		provider := makeProvider(config, name, factory)
		if provider != nil {
			gothProviders = append(gothProviders, provider)
		}
	}
	if len(gothProviders) > 0 {
		goth.UseProviders(gothProviders...)
	} else {
		log.Warning("no oauth providers")
	}
}

func makeProviderFactory(v interface{}) providerFactory {
	return func(clientKey, secret, callbackURL string, scopes ...string) goth.Provider {
		f := reflect.ValueOf(v)
		// f := reflect.FuncOf(v)
		args := []reflect.Value{
			reflect.ValueOf(clientKey),
			reflect.ValueOf(secret),
			reflect.ValueOf(callbackURL),
		}
		for _, scope := range scopes {
			args = append(args, reflect.ValueOf(scope))
		}
		result := f.Call(args)
		return result[0].Interface().(goth.Provider)
	}
}

func makeProvider(config *auth.Config, provider string, factory providerFactory) goth.Provider {
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

	// TODO support scopes via env
	return factory(key, secret, callbackURL)
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
		data := auth.UserData{
			RawData:           account.RawData,
			Provider:          account.Provider,
			Email:             account.Email,
			Name:              account.Name,
			FirstName:         account.FirstName,
			LastName:          account.LastName,
			NickName:          account.NickName,
			Description:       account.Description,
			UserID:            account.UserID,
			AvatarURL:         account.AvatarURL,
			Location:          account.Location,
			AccessToken:       account.AccessToken,
			AccessTokenSecret: account.AccessTokenSecret,
			RefreshToken:      account.RefreshToken,
			ExpiresAt:         account.ExpiresAt,
		}
		user, err = userStore.CreateUser(ctx, data)
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
