package auth

import (
	"context"
	"net/http"
)

const userKey = "user"

// GetRequestUser returns authenticated user for given request
func GetRequestUser(r *http.Request) User {
	var i = r.Context().Value(userKey)
	if i == nil {
		return nil
	}
	return i.(User)
}

func withUser(parent context.Context, user User) context.Context {
	return context.WithValue(parent, userKey, user)
}
