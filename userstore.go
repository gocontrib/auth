package auth

import "context"

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

type StdUser struct {
	ID     string
	Name   string
	Email  string
	Admin  bool
	Claims map[string]interface{}
}

func (u *StdUser) GetID() string {
	return u.ID
}

func (u *StdUser) GetName() string {
	return u.Name
}

func (u *StdUser) GetEmail() string {
	return u.Email
}

func (u *StdUser) IsAdmin() bool {
	return u.Admin
}

func (u *StdUser) GetClaims() map[string]interface{} {
	return u.Claims
}
