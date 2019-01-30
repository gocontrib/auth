package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/cors"
	"github.com/gocontrib/auth"
	"github.com/gocontrib/auth/oauth"
	"github.com/gocontrib/request"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/vk"
)

var port int64 = 3131

func main() {
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: makeAPIHandler(),
	}

	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}

func makeAPIHandler() http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Basic CORS
	// for more ideas, see: https://developer.github.com/v3/#cross-origin-resource-sharing
	cors := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	})
	r.Use(cors.Handler)

	authConfig := &auth.Config{
		UserStore:   &memStore{},
		UserStoreEx: &memStore{},
		ServerPort:  port,
	}
	authConfig = authConfig.SetDefaults()

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		token := request.GetCookie(r, authConfig.TokenCookie)
		fmt.Fprintf(w, "token: %s\n", token)
	})

	oauth.WithProviders(authConfig, "vk", vk.New)
	oauth.RegisterAPI(r, authConfig)

	return r
}

type memStore map[string]*auth.UserInfo

func (m memStore) ValidateCredentials(ctx context.Context, username, password string) (auth.User, error) {
	u, ok := m[username]
	if !ok {
		return nil, errors.New("user not found")
	}
	if u.Pwd != password {
		return nil, errors.New("invalid password")
	}
	return u, nil
}

func (m memStore) FindUserByID(ctx context.Context, userID string) (auth.User, error) {
	for _, u := range m {
		if u.ID == userID || u.Email == userID {
			return u, nil
		}
	}
	return nil, errors.New("user not found")
}

func (m memStore) Close() {
}

func (m memStore) FindUserByEmail(ctx context.Context, userID string) (auth.User, error) {
	return m.FindUserByID(ctx, userID)
}

func (m memStore) CreateUser(ctx context.Context, account goth.User) (auth.User, error) {
	user := &auth.UserInfo{
		ID:    account.UserID,
		Name:  account.Name,
		Email: account.Email,
		Pwd:   "123",
	}
	m[user.Name] = user
	return user, nil
}
