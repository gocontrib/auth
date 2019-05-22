package auth

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

type Token struct {
	UserID    string                 `json:"user_id"`
	UserName  string                 `json:"user_name"`
	Domain    string                 `json:"domain"`
	IssuedAt  Timestamp              `json:"issued_at"`
	ExpiredAt Timestamp              `json:"expired_at"`
	Issuer    string                 `json:"issuer"`
	ClientIP  string                 `json:"client_ip"`
	Claims    map[string]interface{} `json:"claims"` // custom claims
}

func (t *Token) Encode(config *Config) (string, *Error) {
	issuer := t.Issuer
	if len(issuer) == 0 {
		issuer = getIssuer()
	}

	claims := jwt.MapClaims{}

	if t.Claims != nil {
		for k, v := range t.Claims {
			claims[k] = v
		}
	}

	// standard claims
	claims["iss"] = issuer
	claims["iat"] = now().Unix() // issued_at
	claims["user_id"] = t.UserID
	claims["user_name"] = t.UserName
	claims["domain"] = t.Domain
	claims["exp"] = t.ExpiredAt.Unix()

	if len(t.ClientIP) > 0 {
		claims["aud"] = t.ClientIP
	}

	return encodeToken(claims, config)
}

func encodeToken(claims jwt.Claims, config *Config) (string, *Error) {
	token := jwt.NewWithClaims(config.SingingMethod, claims)
	str, err := token.SignedString(config.SecretKey)
	if err != nil {
		return "", ErrEncodeTokenFailed.WithCause(err)
	}
	return str, nil
}

func parseToken(config *Config, tokenString, expectedAudience string, allowExpired bool) (*Token, *Error) {
	parser := new(jwt.Parser)
	parser.SkipClaimsValidation = allowExpired

	claims := jwt.MapClaims{}
	token, err := parser.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return config.SecretKey, nil
	})
	if err != nil {
		return nil, ErrInvalidToken.WithCause(err)
	}
	if !token.Valid {
		return nil, ErrInvalidToken
	}

	issuer := getString(claims, "iss")
	if !claims.VerifyIssuer(issuer, true) {
		return nil, ErrInvalidIssuer
	}

	clientIP := getString(claims, "aud")
	if len(expectedAudience) > 0 && len(clientIP) > 0 && clientIP != expectedAudience {
		return nil, ErrInvalidClientIP
	}

	// check required fields
	userID := getString(claims, "user_id")
	if len(userID) == 0 {
		return nil, ErrMissingUserID
	}

	exp := getTime(claims, "exp")
	if exp == nil {
		return nil, ErrMissingExp
	}

	issuedAt := getTime(claims, "iat")
	if issuedAt == nil {
		t := time.Time{}
		issuedAt = &t
	}

	userName := getString(claims, "user_name")

	return &Token{
		UserID:    userID,
		UserName:  userName,
		Domain:    getString(claims, "domain"),
		IssuedAt:  Timestamp(*issuedAt),
		ExpiredAt: Timestamp(*exp),
		Issuer:    issuer,
		ClientIP:  clientIP,
	}, nil
}
