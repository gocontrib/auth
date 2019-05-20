package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func RegisterHandler(config *Config) http.Handler {
	return RegisterHandlerFunc(config)
}

func RegisterHandlerFunc(config *Config) http.HandlerFunc {
	config = config.SetDefaults()

	return func(w http.ResponseWriter, r *http.Request) {
		// TODO include other fields

		in := &struct {
			Name  string `json:"name"`
			Email string `json:"email"`
			Role  string `json:"role"`
		}{}

		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(in)
		if err != nil {
			SendError(w, ErrBadState.WithCause(err))
			return
		}
		ctx := r.Context()
		userStore := config.UserStoreEx
		user, err := userStore.FindUserByEmail(ctx, in.Email)
		if user != nil {
			SendError(w, ErrBadState.WithCause(fmt.Errorf("such user already exists")))
			return
		}

		account := UserData{
			Name:  in.Name,
			Email: in.Email,
			Role:  in.Role,
		}
		user, err = userStore.CreateUser(ctx, account)
		if err != nil {
			SendError(w, ErrBadState.WithCause(err))
			return
		}

		WriteLoginResponse(w, r, config, user)
	}
}
