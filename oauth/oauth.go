package oauth

import (
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/go-chi/chi"
	"github.com/gocontrib/auth"
	"github.com/gocontrib/request"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	log "github.com/sirupsen/logrus"
)

type providerFactory = func(clientKey, secret, callbackURL string, scopes ...string) goth.Provider

var providerNames []string

// WithProviders registers OAuth providers
// Example:
// import "github.com/markbates/goth/providers/vk"
// oauth.WithProviders("vk", vk.New)
func WithProviders(config *auth.Config, providers ...interface{}) {
	providerNames = []string{}
	var gothProviders []goth.Provider
	for i := 0; i+1 < len(providers); i += 2 {
		name := providers[i].(string)
		factory := makeProviderFactory(providers[i+1])
		provider := makeProvider(config, name, factory)
		if provider != nil {
			providerNames = append(providerNames, name)
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
		log.Warningf("%s has no keys\n", provider)
		return nil
	}

	// TODO detect server supports https
	secure := true
	baseURL := strings.TrimRight(getBaseURL(config, secure), "/")
	callbackURL := baseURL + "/api/oauth/callback/" + provider
	log.Debugf("%s callback: %s\n", provider, callbackURL)

	// TODO support scopes via env
	return factory(key, secret, callbackURL)
}

func getBaseURL(config *auth.Config, secure bool) string {
	scheme := "http"
	portVar := "HTTP_PORT"
	if secure {
		scheme = "https"
		portVar = "HTTPS_PORT"
	}
	hostname := Hostname()
	if port, err := strconv.ParseInt(os.Getenv(portVar), 10, 64); err == nil {
		if !secure && port == 80 || secure && port == 443 {
			return fmt.Sprintf("%s://%s", scheme, hostname)
		}
		return fmt.Sprintf("%s://%s:%d", scheme, hostname, port)
	}
	return fmt.Sprintf("%s://%s", scheme, hostname)
}

// Hostname reads HOSTNAME env var or os.Hostname used for your app
func Hostname() string {
	hostname := os.Getenv("HOSTNAME")
	if len(hostname) > 0 {
		return hostname
	}
	hostname, err := os.Hostname()
	if err == nil {
		return hostname
	}
	return "localhost"
}

// Router interface to allow use of any router
type Router interface {
	Get(pattern string, h http.HandlerFunc)
}

// RegisterAPI registers OAuth HTTP handlers
func RegisterAPI(r Router, config *auth.Config) {
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

	r.Get("/api/oauth/success", func(w http.ResponseWriter, r *http.Request) {
		// TODO print nice html page
		fmt.Fprintf(w, "<body>Hey, buddy!</body>")
	})

	r.Get("/api/oauth/error", func(w http.ResponseWriter, r *http.Request) {
		// TODO print nice html error page
		fmt.Fprintf(w, "<body>Oops, your OAuth failed! Please try again later</body>")
	})

	r.Get("/api/oauth/providers", func(w http.ResponseWriter, r *http.Request) {
		auth.SendJSON(w, providerNames)
	})

	r.Get("/api/oauth/login/{provider}", func(w http.ResponseWriter, r *http.Request) {
		// try to get the user without re-authenticating
		if user, err := gothic.CompleteUserAuth(w, r); err == nil {
			completeOAuthFlow(w, r, config, user)
		} else {
			gothic.BeginAuthHandler(w, r)
		}
	})

	r.Get("/api/oauth/logout/{provider}", func(w http.ResponseWriter, r *http.Request) {
		gothic.Logout(w, r)
		w.Header().Set("Location", "/")
		w.WriteHeader(http.StatusTemporaryRedirect)
	})

	r.Get("/api/oauth/callback/{provider}", func(w http.ResponseWriter, r *http.Request) {
		user, err := gothic.CompleteUserAuth(w, r)
		if err != nil {
			oauthError(w, r, err)
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

	user, err := userStore.FindUserByEmail(ctx, account.Email)
	if err != nil {
		user, err = userStore.CreateUser(ctx, data)
		if err != nil {
			oauthError(w, r, err)
			return
		}
	}

	err = userStore.UpdateAccount(ctx, data)
	if err != nil {
		oauthError(w, r, err)
		return
	}

	token := auth.MakeToken(r, config, user)
	tokenString, err3 := token.Encode(config)
	if err3 != nil {
		oauthError(w, r, err3)
		return
	}

	request.SetCookie(w, r, config.TokenCookie, tokenString)

	// TODO support return_url, absolute url if needed
	http.Redirect(w, r, "/api/oauth/success?token="+tokenString, http.StatusFound)
}

func oauthError(w http.ResponseWriter, r *http.Request, err error) {
	http.Redirect(w, r, "/api/oauth/error?message="+err.Error(), http.StatusInternalServerError)
}
