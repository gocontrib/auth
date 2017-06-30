package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	loginSchema = `{
		"type": "object",
		"properties": {
			"token": {
				"type": "string"
			},
			"user_id": {
				"type": "string"
			},
			"user_name": {
				"type": "string"
			},
			"expired_at": {
				"type": "number"
			}
		},
		"required": ["token", "user_id", "user_name", "expired_at"]
	}`
)

func TestLoginHandler_InvalidContentType(t *testing.T) {
	config := makeTestConfig()
	handler := LoginHandler(config)
	c := makectx(t, httptest.NewServer(handler))
	c.expect.POST("/").WithText("test").Expect().Status(http.StatusUnsupportedMediaType)
}

func TestLoginHandler_ValidCredentialsJSON(t *testing.T) {
	config := makeTestConfig()
	handler := LoginHandler(config)
	c := makectx(t, httptest.NewServer(handler))
	c.expect.POST("/").WithJSON(&Credentials{UserName: "bob", Password: "b0b"}).
		Expect().
		Status(http.StatusOK).
		JSON().
		Schema(loginSchema)
}

func TestLoginHandler_ValidCredentialsForm(t *testing.T) {
	config := makeTestConfig()
	handler := LoginHandler(config)
	c := makectx(t, httptest.NewServer(handler))
	c.expect.POST("/").
		WithFormField("username", "bob").
		WithFormField("password", "b0b").
		Expect().
		Status(http.StatusOK).
		JSON().
		Schema(loginSchema)
}

func TestLoginHandler_InvalidCredentials(t *testing.T) {
	config := makeTestConfig()
	handler := LoginHandler(config)
	c := makectx(t, httptest.NewServer(handler))
	c.expect.POST("/").WithJSON(&Credentials{UserName: "bob", Password: "1"}).
		Expect().
		Status(http.StatusUnauthorized)
}

func TestLoginHandler_UndefinedCredentials(t *testing.T) {
	config := makeTestConfig()
	handler := LoginHandler(config)
	c := makectx(t, httptest.NewServer(handler))
	c.expect.POST("/").WithJSON(&Credentials{}).
		Expect().
		Status(http.StatusUnauthorized)
}

func TestLoginHandler_InvalidJSON(t *testing.T) {
	config := makeTestConfig()
	handler := LoginHandler(config)
	c := makectx(t, httptest.NewServer(handler))
	c.expect.POST("/").WithJSON("invalid").
		Expect().
		Status(http.StatusBadRequest)
}
