package auth

import (
	"golang.org/x/net/context"
	"net/http"
)

const tokenContextKey = "request_token"

// GetToken returns auth token for given request context
func GetToken(r *http.Request) *Token {
	var i = r.Context().Value(tokenContextKey)
	if i == nil {
		return nil
	}
	return i.(*Token)
}

func withToken(r *http.Request, token *Token) context.Context {
	return context.WithValue(r.Context(), tokenContextKey, token)
}
