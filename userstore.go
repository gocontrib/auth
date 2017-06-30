package auth

type User interface {
	GetID() string
	GetName() string
	GetEmail() string
	IsAdmin() bool
}

type UserStore interface {
	ValidateCredentials(username, password string) (User, error)
	FindUserByID(userID string) (User, error)
}
