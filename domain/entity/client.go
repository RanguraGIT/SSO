package entity

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Client represents an OAuth2 client (confidential or public) capable of requesting tokens.
// Does not embed secrets directly beyond hashed/derived forms.
type Client struct {
	ID           uuid.UUID
	ClientID     string
	Name         string
	HashedSecret string // Empty for public clients (PKCE required)
	RedirectURIs []string
	Scopes       []string
	Confidential bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
	PKCERequired bool // Force PKCE even if confidential for defense in depth
}

func NewClient(clientID, name, hashedSecret string, redirectURIs, scopes []string, confidential bool, pkceRequired bool) (*Client, error) {
	if clientID == "" {
		return nil, errors.New("clientID required")
	}
	if name == "" {
		return nil, errors.New("name required")
	}
	if !confidential && hashedSecret != "" {
		return nil, errors.New("public clients must not have a secret")
	}
	if len(redirectURIs) == 0 {
		return nil, errors.New("at least one redirect URI required")
	}
	return &Client{
		ID:           uuid.New(),
		ClientID:     clientID,
		Name:         name,
		HashedSecret: hashedSecret,
		RedirectURIs: redirectURIs,
		Scopes:       scopes,
		Confidential: confidential,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
		PKCERequired: pkceRequired,
	}, nil
}

func (c *Client) Touch() { c.UpdatedAt = time.Now().UTC() }
