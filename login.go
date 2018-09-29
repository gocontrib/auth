package auth

import (
	"encoding/json"
	"mime"
	"net/http"

	"github.com/gorilla/schema"
)

var formDecoder = schema.NewDecoder()

// TODO support user defined expiration
type Credentials struct {
	UserName string `json:"username" schema:"username"`
	Password string `json:"password" schema:"password"`
}

type LoginResponse struct {
	Token     string    `json:"token"`
	UserID    string    `json:"user_id"`
	UserName  string    `json:"user_name"`
	ExpiredAt Timestamp `json:"expired_at"`
}

func LoginHandler(config *Config) http.Handler {
	config = config.setDefaults()
	return http.HandlerFunc(LoginHandlerFunc(config))
}

func LoginHandlerFunc(config *Config) http.HandlerFunc {
	config = config.setDefaults()

	return func(w http.ResponseWriter, r *http.Request) {
		cred, err1 := decodeCredentials(w, r)
		if err1 != nil {
			sendError(w, err1)
			return
		}

		user, err2 := config.UserStore.ValidateCredentials(r.Context(), cred.UserName, cred.Password)
		if err2 != nil {
			sendError(w, errBadCredentials.cause(err2))
			return
		}

		issuedAt := now()
		token := &Token{
			UserID:    user.GetID(),
			UserName:  user.GetName(),
			IssuedAt:  Timestamp(issuedAt),
			ExpiredAt: Timestamp(issuedAt.Add(config.TokenExpiration)),
			ClientIP:  getClientIP(r),
			Claims:    user.GetClaims(),
		}

		tokenString, err3 := token.Encode(config)
		if err3 != nil {
			sendError(w, err3)
			return
		}

		sendJSON(w, &LoginResponse{
			Token:     tokenString,
			UserID:    token.UserID,
			UserName:  token.UserName,
			ExpiredAt: token.ExpiredAt,
		})
	}
}

func decodeCredentials(w http.ResponseWriter, r *http.Request) (*Credentials, *Error) {
	if len(r.Header.Get(authorizationHeader)) > 0 {
		username, password, ok := r.BasicAuth()
		if !ok {
			return nil, errBadAuthorizationHeader
		}
		return &Credentials{username, password}, nil
	}

	result := &Credentials{}
	err := decodePayload(w, r, result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func decodePayload(w http.ResponseWriter, r *http.Request, payload interface{}) *Error {
	contentType := r.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return errUnsupportedContentType.cause(err)
	}

	if mediaType == contentJSON {
		err = json.NewDecoder(r.Body).Decode(payload)
		if err != nil {
			return errMalformedContent.cause(err)
		}
		return nil
	}

	if mediaType == contentForm {
		err = r.ParseForm()
		if err != nil {
			return errUnsupportedContentType.cause(err)
		}
		err = formDecoder.Decode(payload, r.PostForm)
		if err != nil {
			return errMalformedContent.cause(err)
		}
		return nil
	}

	return errUnsupportedContentType
}
