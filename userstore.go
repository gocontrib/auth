package auth

type User interface {
	GetID() string
	GetEmail() string
}

type UserStore interface {
	ValidateCredentials(username, password string) (User, error)
	FindUserByID(userID string) (User, error)
}
