package repository

type RepositoryWrapper struct {
	AuthorizationCodeRepository AuthorizationCodeRepository
	ClientRepository            ClientRepository
	SessionRepository           SessionRepository
	UserRepository              UserRepository
}
