package usecase

// Wrapper groups usecase interfaces for easy wiring.
type UsecaseWrapper struct {
	StartAuth    StartAuthorization
	IssueToken   IssueToken
	Refresh      RefreshToken
	CreateSess   CreateSession
	UserLogin    UserLogin
	RegisterUser RegisterUser
}
