package request

// LoginRequest represents the JSON body for POST /login
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
