package models

import "github.com/golang-jwt/jwt/v5"

type MSClaims struct {
	Aud         string   `json:"aud"`
	Iss         string   `json:"iss"`
	Iat         int      `json:"iat"`
	Nbf         int      `json:"nbf"`
	Exp         int      `json:"exp"`
	Acr         string   `json:"acr"`
	Aio         string   `json:"aio"`
	Amr         []string `json:"amr"`
	Appid       string   `json:"appid"`
	Appidacr    string   `json:"appidacr"`
	Family_name string   `json:"family_name"`
	Given_name  string   `json:"given_name"`
	Ipaddr      string   `json:"ipaddr"`
	Name        string   `json:"name"`
	Oid         string   `json:"oid"`
	Onprem_sid  string   `json:"onprem_sid"`
	Rh          string   `json:"rh"`
	Roles       []string `json:"roles"`
	Scp         string   `json:"scp"`
	Sub         string   `json:"sub"`
	Tid         string   `json:"tid"`
	Unique_name string   `json:"unique_name"`
	Upn         string   `json:"upn"`
	Uti         string   `json:"uti"`
	Ver         string   `json:"ver"`
	jwt.RegisteredClaims
}

type Key struct {
	Kid string   `json:"kid"`
	X5c []string `json:"x5c"`
}
