package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

var b64 = base64.URLEncoding

type Header struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
}

type Claims map[string]interface{}

func SignHS256(claims Claims, secret []byte) (string, error) {
	rawHeader, err := json.Marshal(Header{
		Typ: "JWT",
		Alg: "HS256",
	})
	if err != nil {
		return "", err
	}
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

func ParseHS256(token string, secret []byte) (Claims, error) {
	chunks := strings.Split(token, ".")
	if len(chunks) != 3 {
		return nil, errors.New("malformed token")
	}
	
	decodedHeader, err := b64.DecodeString(chunks[0])
	if err != nil {
		return nil, err
	}
	
	var header Header
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
	
	return claims, nil
}
