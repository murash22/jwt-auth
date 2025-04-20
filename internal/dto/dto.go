package dto

type GenerateTokensPairInput struct {
	UserId string
	Addr   string
}

type GenerateTokensPairOutput struct {
	AccessToken  string
	RefreshToken string
}

type UpdateTokensInput struct {
	RefreshToken string
	Addr         string
}

type UpdateTokensOutput struct {
	GenerateTokensPairOutput
	OldRefreshTokenClaims JwtPayload
}

type JwtPayload struct {
	Subject string
	Exp     int64
	Addr    string
}
