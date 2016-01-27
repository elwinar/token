package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var b64 = base64.URLEncoding

type header struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
}

// Claims is the type of the token's body. It is basically an alias of map to
// be more readable and easy to use.
type Claims map[string]interface{}

// SignHS256 encode a set of claims in a HS256 encoded token.
func SignHS256(claims Claims, secret []byte) (string, error) {
	rawHeader, _ := json.Marshal(header{
		Typ: "JWT",
		Alg: "HS256",
	}) // Skipping the error because the error isn't input-dependant and thus
	// can't happen during execution.
	encodedHeader := b64.EncodeToString(rawHeader)

	rawClaims, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encodedClaims := b64.EncodeToString(rawClaims)

	h := hmac.New(sha256.New, secret)
	h.Write([]byte(encodedHeader + "." + encodedClaims))
	rawSignature := h.Sum(nil)
	encodedSignature := b64.EncodeToString(rawSignature)

	return encodedHeader + "." + encodedClaims + "." + encodedSignature, nil
}

// ParseHS256 parse and validate a HS256-encoded token. For now, it doesn't
// check anything else than the signature.
func ParseHS256(token string, secret []byte) (Claims, error) {
	chunks := strings.Split(token, ".")
	if len(chunks) != 3 {
		return nil, errors.New("malformed token")
	}

	decodedHeader, err := b64.DecodeString(chunks[0])
	if err != nil {
		return nil, err
	}

	var header header
	err = json.Unmarshal(decodedHeader, &header)
	if err != nil {
		return nil, err
	}

	if header.Typ != "JWT" {
		return nil, errors.New("invalid token type")
	}

	if header.Alg != "HS256" {
		return nil, errors.New("invalid token algorithm")
	}

	h := hmac.New(sha256.New, secret)
	h.Write([]byte(chunks[0] + "." + chunks[1]))
	rawSignature := h.Sum(nil)
	decodedSignature, err := b64.DecodeString(chunks[2])
	if err != nil {
		return nil, err
	}

	if !hmac.Equal(rawSignature, decodedSignature) {
		return nil, errors.New("invalid signature")
	}

	var claims Claims
	decodedClaims, err := b64.DecodeString(chunks[1])
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(decodedClaims, &claims)
	if err != nil {
		return nil, err
	}

	if exp, found := claims["exp"]; found {
		exp, ok := exp.(int64)
		if !ok {
			return nil, errors.New("exp claim must be a NumericalDate")
		}

		if time.Unix(exp, 0).Before(time.Now()) {
			return nil, errors.New("expired token")
		}
	}

	return claims, nil
}
