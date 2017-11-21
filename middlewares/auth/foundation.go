package auth

import (
	"net/http"
	"os"
	"strings"

	"github.com/containous/traefik/types"
	"github.com/dgrijalva/jwt-go"
)

func contains(e string) bool {
	for k := range bypass {
		if strings.HasPrefix(e, k) {
			return true
		}
	}
	return false
}

var bypass = make(map[string]bool)

//UpdateBypassAddress .
func UpdateBypassAddress(address string) {
	bypass[address] = true
}

//ResetBypassAddresses .
func ResetBypassAddresses() {
	bypass = make(map[string]bool)
}

// Foundation the authentication to a external server
func Foundation(config *types.Foundation, w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if !contains(r.URL.RequestURI()) {
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
