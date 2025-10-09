package handler

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/RanguraGIT/sso/domain/usecase"
	req "github.com/RanguraGIT/sso/infrastructure/delivery/http/request"
	resp "github.com/RanguraGIT/sso/infrastructure/delivery/http/response"
)

type RegisterHandler struct{ UC usecase.RegisterUser }

func (h *RegisterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		log.Printf("register: wrong method %s", r.Method)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body req.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		log.Printf("register: decode error: %v", err)
		resp.JSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	out, err := h.UC.Execute(r.Context(), usecase.RegisterUserInput{Email: body.Email, Password: body.Password})
	if err != nil {
		log.Printf("register: execute error: %v", err)
		resp.JSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	log.Printf("register: user created id=%s email=%s", out.UserID, body.Email)
	resp.JSON(w, http.StatusOK, map[string]string{"user_id": out.UserID})
}
