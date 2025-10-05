package mysql

import (
	"context"
	"database/sql"
	"strings"

	"github.com/RanguraGIT/sso/domain/entity"
	"github.com/RanguraGIT/sso/domain/repository"
	"github.com/google/uuid"
)

type SessionRepo struct{ db *sql.DB }

func NewSessionRepo(db *sql.DB) repository.SessionRepository { return &SessionRepo{db: db} }

func (r *SessionRepo) Create(ctx context.Context, s *entity.Session) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO sessions(id,user_id,client_ids,ip,user_agent,expires_at,revoked,created_at) VALUES (?,?,?,?,?,?,?,?)`, s.ID.String(), s.UserID.String(), joinUUIDs(s.ClientIDs), s.IP, s.UserAgent, s.ExpiresAt, s.Revoked, s.CreatedAt)
	return err
}

func (r *SessionRepo) Get(ctx context.Context, id uuid.UUID) (*entity.Session, error) {
	row := r.db.QueryRowContext(ctx, `SELECT id,user_id,client_ids,ip,user_agent,expires_at,revoked,created_at FROM sessions WHERE id=?`, id.String())
	s := &entity.Session{}
	var clientIDs string
	if err := row.Scan(&s.ID, &s.UserID, &clientIDs, &s.IP, &s.UserAgent, &s.ExpiresAt, &s.Revoked, &s.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if strings.TrimSpace(clientIDs) != "" {
		s.ClientIDs = parseUUIDs(clientIDs)
	}
	return s, nil
}

func (r *SessionRepo) AddClient(ctx context.Context, id uuid.UUID, clientID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `UPDATE sessions SET client_ids=CONCAT(IFNULL(client_ids,''), ' ', ?) WHERE id=?`, clientID.String(), id.String())
	return err
}

func (r *SessionRepo) Revoke(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `UPDATE sessions SET revoked=1 WHERE id=?`, id.String())
	return err
}

func joinUUIDs(ids []uuid.UUID) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, id.String())
	}
	return strings.Join(parts, " ")
}

func parseUUIDs(s string) []uuid.UUID {
	parts := strings.Fields(s)
	out := make([]uuid.UUID, 0, len(parts))
	for _, p := range parts {
		if u, err := uuid.Parse(p); err == nil {
			out = append(out, u)
		}
	}
	return out
}
