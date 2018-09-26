package auth

import "context"

type User interface {
	GetID() string
	GetName() string
	GetEmail() string
	IsAdmin() bool
}

type UserStore interface {
	ValidateCredentials(ctx context.Context, username, password string) (User, error)
	FindUserByID(ctx context.Context, userID string) (User, error)
	Close()
}
