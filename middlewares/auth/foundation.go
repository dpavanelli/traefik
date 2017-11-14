package auth

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/containous/traefik/types"
	"github.com/dgrijalva/jwt-go"
)

func contains(s []string, e string) bool {
	for _, a := range s {
		if strings.HasPrefix(e, a) {
			return true
		}
	}
	return false
}

var data int

// Foundation the authentication to a external server
func Foundation(config *types.Foundation, w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	fmt.Printf("\n------> Valor atual: %v", data)
	data++
	if !contains(config.Bypass, r.URL.RequestURI()) {
		foundationID, _ := r.Cookie("FOUNDATIONID")
		if foundationID == nil || len(foundationID.Value) == 0 {
			r.URL.RawQuery = "callback=foundation"
			r.URL.Path = "/accounts/login"
		} else {
			token, _ := jwt.Parse(foundationID.Value, func(token *jwt.Token) (interface{}, error) {
				return []byte(os.Getenv("JWT_KEY")), nil
			})
			if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				r.Header.Add("login", claims["login"].(string))
			} else {
				r.URL.RawQuery = "callback=foundation"
				r.URL.Path = "/accounts/login"
			}
		}
	}
	r.RequestURI = r.URL.RequestURI()
	next(w, r)
}
