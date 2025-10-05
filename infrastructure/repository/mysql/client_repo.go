package mysql

import (
	"context"
	"database/sql"
	"strings"

	"github.com/RanguraGIT/sso/domain/entity"
	"github.com/RanguraGIT/sso/domain/repository"
)

type ClientRepo struct{ db *sql.DB }

func NewClientRepo(db *sql.DB) repository.ClientRepository { return &ClientRepo{db: db} }

func (r *ClientRepo) GetByClientID(ctx context.Context, clientID string) (*entity.Client, error) {
	row := r.db.QueryRowContext(ctx, `SELECT id,client_id,name,hashed_secret,redirect_uris,scopes,confidential,pkce_required,created_at,updated_at FROM clients WHERE client_id=?`, clientID)
	c := &entity.Client{}
	var redirectURIs, scopes string
	if err := row.Scan(&c.ID, &c.ClientID, &c.Name, &c.HashedSecret, &redirectURIs, &scopes, &c.Confidential, &c.PKCERequired, &c.CreatedAt, &c.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	c.RedirectURIs = splitNonEmpty(redirectURIs)
	c.Scopes = splitNonEmpty(scopes)
	return c, nil
}

func (r *ClientRepo) Create(ctx context.Context, c *entity.Client) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO clients(id,client_id,name,hashed_secret,redirect_uris,scopes,confidential,pkce_required,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)`, c.ID.String(), c.ClientID, c.Name, c.HashedSecret, strings.Join(c.RedirectURIs, " "), strings.Join(c.Scopes, " "), c.Confidential, c.PKCERequired, c.CreatedAt, c.UpdatedAt)
	return err
}

func (r *ClientRepo) Update(ctx context.Context, c *entity.Client) error {
	_, err := r.db.ExecContext(ctx, `UPDATE clients SET name=?, hashed_secret=?, redirect_uris=?, scopes=?, confidential=?, pkce_required=?, updated_at=NOW(6) WHERE client_id=?`, c.Name, c.HashedSecret, strings.Join(c.RedirectURIs, " "), strings.Join(c.Scopes, " "), c.Confidential, c.PKCERequired, c.ClientID)
	return err
}

func splitNonEmpty(s string) []string {
	parts := strings.Fields(s)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
