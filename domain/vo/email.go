package vo

import (
	"errors"
	"net/mail"
	"strings"

)

// Email is a validated email value object.
// Immutable after creation to preserve invariant of RFC compliance.
type Email struct {
	value string
}

func NewEmail(v string) (Email, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return Email{}, errors.New("email required")
	}
	if _, err := mail.ParseAddress(v); err != nil {
		return Email{}, err
	}
	return Email{value: strings.ToLower(v)}, nil
}

func (e Email) String() string { return e.value }
