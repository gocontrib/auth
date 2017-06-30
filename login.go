package auth

import (
	"encoding/json"
	"net/http"
)

// TODO support user defined expiration
type Credentials struct {
	UserName string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token     string    `json:"token"`
	UserID    string    `json:"user_id"`
	UserName  string    `json:"username"`
	ExpiredAt Timestamp `json:"expired_at"`
}

func LoginHandler(config *Config) http.Handler {
	config = config.setDefaults()

	fn := func(w http.ResponseWriter, r *http.Request) {
		// TODO support other content-type
		contentType := r.Header.Get("Content-Type")
		input := &Credentials{}

		if contentType == contentJSON {
			err := json.NewDecoder(r.Body).Decode(input)
			if err != nil {
				sendError(w, errInvalidLoginPayload, http.StatusBadRequest)
				return
			}
		} else {
			sendError(w, errUnsupportedContentType, http.StatusBadRequest)
			return
		}

		user, err := config.UserStore.ValidateCredentials(input.UserName, input.Password)
		if err != nil {
			sendError(w, errInvalidCredentials, http.StatusBadRequest)
			return
		}

		issuedAt := now()
		token := &Token{
			UserID:    user.GetID(),
			UserName:  user.GetName(),
			IssuedAt:  Timestamp(issuedAt),
			ExpiredAt: Timestamp(issuedAt.Add(config.TokenExpiration)),
			ClientID:  getClientIP(r),
		}

		tokenString, err := token.Encode(config)
		if err != nil {
			sendError(w, err, http.StatusInternalServerError)
			return
		}

		sendJSON(w, &LoginResponse{
			Token:     tokenString,
			UserID:    token.UserID,
			UserName:  token.UserName,
			ExpiredAt: token.ExpiredAt,
		})
	}
	return http.HandlerFunc(fn)
}
