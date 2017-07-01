package auth

import (
	"encoding/json"
	"github.com/gorilla/schema"
	"mime"
	"net/http"
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

	fn := func(w http.ResponseWriter, r *http.Request) {
		cred := &Credentials{}
		err := decodePayload(w, r, cred)
		if err != nil {
			return
		}

		user, err := config.UserStore.ValidateCredentials(cred.UserName, cred.Password)
		if err != nil {
			sendError(w, errBadCredentials.cause(err))
			return
		}

		issuedAt := now()
		token := &Token{
			UserID:    user.GetID(),
			UserName:  user.GetName(),
			IssuedAt:  Timestamp(issuedAt),
			ExpiredAt: Timestamp(issuedAt.Add(config.TokenExpiration)),
			ClientIP:  getClientIP(r),
		}

		tokenString, error := token.Encode(config)
		if error != nil {
			sendError(w, error)
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

func decodePayload(w http.ResponseWriter, r *http.Request, payload interface{}) error {
	contentType := r.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		sendError(w, errUnsupportedContentType)
		return err
	}

	if mediaType == contentJSON {
		err = json.NewDecoder(r.Body).Decode(payload)
		if err != nil {
			sendError(w, errMalformedContent)
			return err
		}
		return nil
	}

	if mediaType == contentForm {
		err = r.ParseForm()
		if err != nil {
			sendError(w, errUnsupportedContentType)
			return err
		}
		err = formDecoder.Decode(payload, r.PostForm)
		if err != nil {
			sendError(w, errMalformedContent)
			return err
		}
		return nil
	}

	sendError(w, errUnsupportedContentType)
	return errUnsupportedContentType
}
