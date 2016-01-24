package token

import (
	"errors"
	"reflect"
	"testing"
)

type InvalidMarshaller struct{}

func (b InvalidMarshaller) MarshalJSON() ([]byte, error) {
	return nil, errors.New("error")
}

func TestSignHS256(t *testing.T) {
	for i, c := range []struct {
		claims Claims
		secret []byte
		token  string
		err    bool
	}{
		{
			claims: Claims{
				"user": "jackmarshall",
			},
			secret: []byte("secret"),
			token:  "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiamFja21hcnNoYWxsIn0=.37bL9nsSNiCJdzS9QTPwNkk05LN4mqbXFDJZs6SmW-U=",
			err:    false,
		},
		{
			claims: Claims{
				"user": InvalidMarshaller{},
			},
			secret: []byte("secret"),
			token:  "",
			err:    true,
		},
	} {
		token, err := SignHS256(c.claims, c.secret)

		if (err != nil) != c.err {
			if c.err == false {
				t.Log("case", i, "unexpected error:", err)
			} else {
				t.Log("case", i, "expected error")
			}
			t.Fail()
		}

		if token != c.token {
			t.Log("case", i, "unexpected result:\n\tgot:", token, "\n\texpected:", c.token)
			t.Fail()
		}
	}
}

func TestParseHS256(t *testing.T) {
	for i, c := range []struct {
		token  string
		secret []byte
		claims Claims
		err    bool
	}{
		{
			token:  "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiamFja21hcnNoYWxsIn0=.37bL9nsSNiCJdzS9QTPwNkk05LN4mqbXFDJZs6SmW-U=",
			secret: []byte("secret"),
			claims: Claims{
				"user": "jackmarshall",
			},
			err: false,
		},
		{
			token:  "thisisnotavalidtoken",
			secret: []byte("secret"),
			claims: nil,
			err:    true,
		},
		{
			token:  "thisisnot.a.validtoken",
			secret: []byte("secret"),
			claims: nil,
			err:    true,
		},
		{
			token:  "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiamFja21hcnNoYWxsIn0=.37bL9nsSNiCJdzS9QTPwNkk05LN4mqbXFDJZs6SmW-U=",
			secret: []byte("wrongsecret"),
			claims: nil,
			err:    true,
		},
		{
			token:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkZPTyJ9.eyJ1c2VyIjoiamFja21hcnNoYWxsIn0.24fzAfkjlaH19JISrLgucD7y2wFvYxZZj8Q3X3g7Vrw", // Not HS256
			secret: []byte("secret"),
			claims: nil,
			err:    true,
		},
		{
			token:  "eyJhbGciOiJCQVIiLCJ0eXAiOiJKV1QifQ.eyJ1c2VyIjoiamFja21hcnNoYWxsIn0.xSpQCtwGO3BIXxBpCPh_yhYJuNyOaWG1IqCxRXEqTrE", // Not JWT
			secret: []byte("secret"),
			claims: nil,
			err:    true,
		},
		{
			token:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ8.eyJ1c2VyIjoiamFja21hcnNoYWxsIn0.Tlsu8ZoDEuMAHq8BBEFjOSKpA0FYjnoVtqlM_L9RjIA", // Invalid JSON in header
			secret: []byte("secret"),
			claims: nil,
			err:    true,
		},
		{
			token:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiamFja21hcnNoYWxsIn1.Tlsu8ZoDEuMAHq8BBEFjOSKpA0FYjnoVtqlM_L9RjIA", // Invalid JSON in claims
			secret: []byte("secret"),
			claims: nil,
			err:    true,
		},
		{
			token:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVC J9.eyJ1c2VyIjoiamFja21hcnNoYWxsIn0.Tlsu8ZoDEuMAHq8BBEFjOSKpA0FYjnoVtqlM_L9RjIA", // Invalid base64 in header
			secret: []byte("secret"),
			claims: nil,
			err:    true,
		},
		{
			token:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ8.eyJ1c2VyIjoiamFja21hcnNoYWx sIn1.Tlsu8ZoDEuMAHq8BBEFjOSKpA0FYjnoVtqlM_L9RjIA", // Invalid base64 in claims
			secret: []byte("secret"),
			claims: nil,
			err:    true,
		},
		{
			token:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ8.eyJ1c2VyIjoiamFja21hcnNoYWxsIn1.Tlsu8ZoDEuMAHq8BBEFj OSKpA0FYjnoVtqlM_L9RjIA", // Invalid base64 in signature
			secret: []byte("secret"),
			claims: nil,
			err:    true,
		},
	} {
		claims, err := ParseHS256(c.token, c.secret)

		if (err != nil) != c.err {
			if c.err == false {
				t.Log("case", i, "unexpected error:", err)
			} else {
				t.Log("case", i, "expected error")
			}
			t.Fail()
		}

		if !reflect.DeepEqual(claims, c.claims) {
			t.Log("case", i, "unexpected result:\n\tgot:", claims, "\n\texpected:", c.claims)
			t.Fail()
		}
	}
}
