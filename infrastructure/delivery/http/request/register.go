package request

// RegisterRequest represents POST /register JSON body
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
