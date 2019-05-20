package auth

import (
	"net/http"
)

func CheckTokenHandler(config *Config) http.Handler {
	return CheckTokenHandlerFunc(config)
}

func CheckTokenHandlerFunc(config *Config) http.HandlerFunc {
	config = config.SetDefaults()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		scheme, tokenString, err := parseAuthorizationHeader(auth)
		if err == nil && scheme != schemeBearer {
			err = ErrUnsupportedAuthScheme
		}
		if err != nil {
			SendError(w, err)
			return
		}
		_, user, err := validateJWT(config, r, tokenString)
		if err != nil {
			SendError(w, err)
			return
		}
		WriteLoginResponse(w, r, config, user)
	})
}
