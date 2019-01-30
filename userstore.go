package auth

import (
	"context"

	"github.com/markbates/goth"
)

type User interface {
	GetID() string
	GetName() string
	GetEmail() string
	IsAdmin() bool
	GetClaims() map[string]interface{}
}

type UserStore interface {
	ValidateCredentials(ctx context.Context, username, password string) (User, error)
	FindUserByID(ctx context.Context, userID string) (User, error)
	Close()
}

type UserStoreEx interface {
	FindUserByEmail(ctx context.Context, userID string) (User, error)
	CreateUser(ctx context.Context, account goth.User) (User, error)
}

type UserInfo struct {
	ID     string
	Name   string
	Email  string
	Admin  bool
	Claims map[string]interface{}
	Pwd    string // for testing purposes
}

func (u *UserInfo) GetID() string {
	return u.ID
}

func (u *UserInfo) GetName() string {
	return u.Name
}

func (u *UserInfo) GetEmail() string {
	return u.Email
}

func (u *UserInfo) IsAdmin() bool {
	return u.Admin
}

func (u *UserInfo) GetClaims() map[string]interface{} {
	return u.Claims
}
