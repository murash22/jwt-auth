package dto

type TokensPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type GenerateTokensPairInput struct {
	UserId    string
	Addr      string
	UserAgent string
}

type GenerateTokensPairOutput struct {
	TokensPair
}

type UpdateTokensInput struct {
	AccessToken  string
	RefreshToken string
	Addr         string
	UserAgent    string
}

type UpdateTokensOutput struct {
	TokensPair
}

type JwtPayload struct {
	Subject string
	Exp     int64
}
