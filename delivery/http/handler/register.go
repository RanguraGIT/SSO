package handler

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/RanguraGIT/sso/infrastructure/usecase"
)

type RegisterHandler struct{ UC *usecase.RegisterUser }

type registerReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *RegisterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		log.Printf("register: wrong method %s", r.Method)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req registerReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("register: decode error: %v", err)
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	out, err := h.UC.Execute(r.Context(), usecase.RegisterUserInput{Email: req.Email, Password: req.Password})
	if err != nil {
		log.Printf("register: execute error: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("register: user created id=%s email=%s", out.UserID, req.Email)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"user_id": out.UserID})
}
