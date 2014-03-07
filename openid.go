// OpenID Connect

package osin

import (
    "github.com/dgrijalva/jwt-go"

    "errors"
    "net/http"
    "strconv"
    "strings"
    "time"
)

// OpenID Connect id_token data
type IdTokenData struct {
    Iss string // Required: Issuer
    Sub string // Required: Subject (user identifier)
    Aud string // Required: Audience (must contain at least the client id)

    Exp      uint32 // Optional: expiration time
    Azp      string // Optional: authorized party
    AuthTime uint32 // Optional: Authentication time (required if MaxAge is set)

    Nonce  string // Automatic: nonce from client request
    Iat    uint32 // Automatic: issue time
    AtHash string // Automatic: first half of access token  TODO: implement

    tokenStr string // Internal
}

func idTokenErr(what string) error {
    return errors.New(what + " is required for the ID token")
}

type ErrorAuthExpired struct {
    exp uint32
    now uint32
}

func (e ErrorAuthExpired) Error() string {
    return "Authentication time expired"
}

// Populates the IdTokenData structure with some additional info from the request.
// Note: in the case that the user's authenticated
// session has expired, the error ErrorAuthExpired will be returned.  The
// application may check for this error and redirect the user to the login
// page.
func PopulateIdToken(r *http.Request, td *IdTokenData) (err error) {
    // XXX: nonce is REQUIRED during Implicit Flow
    td.Nonce = r.Form.Get("nonce")

    var maxAge int
    maxAgeVal := r.Form.Get("max_age")

    if maxAgeVal != "" {
        maxAge, err = strconv.Atoi(maxAgeVal)
        if err != nil {
            return
        }
        if td.AuthTime == 0 {
            err = errors.New("Authentication time (AuthTime) is required for the ID token when max_age is specified")
            return
        }

        maxAge := uint32(maxAge)
        now := uint32(time.Now().Unix())
        if now-td.AuthTime > maxAge {
            err = ErrorAuthExpired{td.AuthTime + maxAge, now}
            return
        }
    }
    return
}

// Generate the id_token.
func GenerateIdToken(ar *AuthorizeData) (err error) {
    token := jwt.New(jwt.GetSigningMethod("RS256"))
    if ar.IdTokenData.Iss == "" {
        return idTokenErr("Issuer")
    }
    token.Claims["iss"] = ar.IdTokenData.Iss

    if ar.IdTokenData.Sub == "" {
        return idTokenErr("Subject")
    }
    token.Claims["sub"] = ar.IdTokenData.Sub

    if ar.IdTokenData.Aud == "" {
        return idTokenErr("Audience")
    }
    token.Claims["aud"] = ar.IdTokenData.Aud

    if ar.IdTokenData.Exp == 0 {
        ar.IdTokenData.Exp = uint32(ar.ExpireAt().Unix())
    }
    token.Claims["exp"] = ar.IdTokenData.Exp

    token.Claims["iat"] = time.Now().Unix()

    if ar.IdTokenData.AuthTime > 0 {
        token.Claims["auth_time"] = ar.IdTokenData.AuthTime
    }

    if ar.IdTokenData.Nonce != "" {
        token.Claims["nonce"] = ar.IdTokenData.Nonce
    }

    // acr not supported
    // amr not supported

    // If Azp is present, it must contain the client id. If the caller didn't
    // supply it, we add it instead of returning an error.
    if ar.IdTokenData.Azp != "" {
        var found bool
        words := strings.Fields(ar.IdTokenData.Azp)

        for _, v := range words {
            if v == ar.Client.Id {
                found = true
                break
            }
        }
        if !found {
            words = append(words, ar.Client.Id)
        }

        token.Claims["azp"] = strings.Join(words, " ")
    }

    if len(ar.SigningKey) == 0 {
        return idTokenErr("Token signing key")
    }

    ar.IdTokenData.tokenStr, err = token.SignedString([]byte(ar.SigningKey))
    return

}
