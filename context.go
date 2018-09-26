package auth

import (
	"context"
	"net/http"
)

const userKey = "user"

// GetRequestUser returns authenticated user for given request
func GetRequestUser(r *http.Request) User {
	return GetContextUser(r.Context())
}

// GetContextUser returns authenticated user if it presents in given context
func GetContextUser(c context.Context) User {
	var i = c.Value(userKey)
	if i == nil {
		return nil
	}
	return i.(User)
}

// WithUser returns new context with given user
func WithUser(parent context.Context, user User) context.Context {
	return context.WithValue(parent, userKey, user)
}
