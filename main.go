package main

import (
	"crypto/ecdsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

type CustomClaimsExample struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	LastName string `json:"lastname"`
	jwt.StandardClaims
}

func CreateToken(claims CustomClaimsExample, signingKey []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(signingKey)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

func ParseToken(tokenString string, signingKey []byte) (*CustomClaimsExample, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaimsExample{}, func(token *jwt.Token) (interface{}, error) {
		return signingKey, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*CustomClaimsExample); ok && token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid token")
}

func ReadJWT(tokenString string, key *ecdsa.PrivateKey) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaimsExample{}, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(token)
}

func main() {
	signingKey := []byte("123-signed-key")

	claims := CustomClaimsExample{
		ID:       "1",
		Name:     "Nicolas",
		LastName: "Aguilar",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(), // Token expires in 24 hours
			IssuedAt:  time.Now().Unix(),
			Issuer:    "your-issuer",
		},
	}

	tokenString, err := CreateToken(claims, signingKey)

	if err != nil {
		fmt.Println("Error creating token:", err)
		return
	}

	fmt.Println("Generated JWT token:", tokenString)

	parsedClaims, err := ParseToken(tokenString, signingKey)

	if err != nil {
		fmt.Println("Error parsing token:", err)
		return
	}

	fmt.Printf("Parsed claims: %+v\n", parsedClaims)
}
