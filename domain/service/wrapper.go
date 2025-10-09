package service

type ServiceWrapper struct {
	AuthService        AuthService
	TokenService       TokenService
	KeyRotationService KeyRotationService
}
