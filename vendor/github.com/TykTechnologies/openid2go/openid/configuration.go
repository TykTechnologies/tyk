package openid

type configuration struct {
	Issuer  string `json:"issuer"`
	JwksUri string `json:"jwks_uri"`
}
