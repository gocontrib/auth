package auth

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

type Token struct {
	UserID    string    `json:"user_id"`
	UserName  string    `json:"user_name"`
	Domain    string    `json:"domain"`
	IssuedAt  Timestamp `json:"issued_at"`
	ExpiredAt Timestamp `json:"expired_at"`
	Issuer    string    `json:"issuer"`
	ClientID  string    `json:"client_id"`
}

func (t *Token) Encode(config *Config) (string, error) {
	issuer := t.Issuer
	if len(issuer) == 0 {
		issuer = getIssuer()
	}
	claims := jwt.MapClaims{
		"iss":       issuer,
		"iat":       now().Unix(), // issued_at
		"user_id":   t.UserID,
		"user_name": t.UserName,
		"domain":    t.Domain,
		"exp":       t.ExpiredAt.Unix(),
	}
	if len(t.ClientID) > 0 {
		claims["aud"] = t.ClientID
	}
	return encodeToken(claims, config)
}

func encodeToken(claims jwt.Claims, config *Config) (string, error) {
	token := jwt.NewWithClaims(config.SingingMethod, claims)
	return token.SignedString(config.SecretKey)
}

func parseToken(config *Config, tokenString, expectedAudience string, allowExpired bool) (*Token, error) {
	parser := new(jwt.Parser)
	parser.SkipClaimsValidation = allowExpired

	claims := jwt.MapClaims{}
	token, err := parser.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return config.SecretKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errInvalidToken
	}

	issuer := getString(claims, "iss")
	if !claims.VerifyIssuer(issuer, true) {
		// TODO return better error, i.e. "not my token"
		return nil, errInvalidToken
	}

	audience := getString(claims, "aud")
	if len(expectedAudience) > 0 && audience != expectedAudience {
		// TODO return better error, i.e. "token issued for another IP address"
		return nil, errInvalidToken
	}

	// check required fields
	userID := getString(claims, "user_id")
	userName := getString(claims, "user_name")
	if len(userID) == 0 {
		return nil, errInvalidToken
	}

	start := getTime(claims, "start")
	exp := getTime(claims, "exp")
	if start == nil || exp == nil {
		return nil, errInvalidToken
	}

	issuedAt := getTime(claims, "iat")
	if issuedAt == nil {
		t := time.Time{}
		issuedAt = &t
	}

	return &Token{
		UserID:    userID,
		UserName:  userName,
		Domain:    getString(claims, "domain"),
		IssuedAt:  Timestamp(*issuedAt),
		ExpiredAt: Timestamp(*exp),
		Issuer:    issuer,
		ClientID:  audience,
	}, nil
}
