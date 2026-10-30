package pg

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

type User struct {
	ID           int64
	Username     string
	PasswordHash string
	Role         string
	Disabled     bool
	CreatedAt    time.Time
	LastLoginAt  *time.Time
}

type APIToken struct {
	ID         int64
	UserID     int64
	Username   string
	Label      string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	Revoked    bool
}

const userCols = "u.id, u.username, u.password_hash, u.role, u.disabled, u.created_at, u.last_login_at"

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Disabled, &u.CreatedAt, &u.LastLoginAt)
	return u, mapErr(err)
}

func (s *Store) CreateUser(ctx context.Context, username, passwordHash, role string) (User, error) {
	return scanUser(s.pool.QueryRow(ctx,
		`INSERT INTO users AS u (username, password_hash, role) VALUES ($1, $2, $3) RETURNING `+userCols,
		username, passwordHash, role))
}

func (s *Store) UserByUsername(ctx context.Context, username string) (User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users u WHERE u.username = $1`, username))
}

func (s *Store) Users(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+userCols+` FROM users u ORDER BY u.username`)
	return collect(rows, err, scanUser)
}

// SetPassword also drops the user's sessions.
func (s *Store) SetPassword(ctx context.Context, username, passwordHash string) error {
	return s.updateUser(ctx, username, `UPDATE users SET password_hash = $2 WHERE username = $1`, passwordHash)
}

func (s *Store) SetRole(ctx context.Context, username, role string) error {
	return s.updateUser(ctx, username, `UPDATE users SET role = $2 WHERE username = $1`, role)
}

func (s *Store) SetDisabled(ctx context.Context, username string, disabled bool) error {
	return s.updateUser(ctx, username, `UPDATE users SET disabled = $2 WHERE username = $1`, disabled)
}

func (s *Store) updateUser(ctx context.Context, username, query string, arg any) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := affected(tx.Exec(ctx, query, username, arg)); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE username = $1)`, username)
		return mapErr(err)
	})
}

func (s *Store) TouchLogin(ctx context.Context, userID int64) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET last_login_at = now() WHERE id = $1`, userID)
	return mapErr(err)
}

func (s *Store) CreateSession(ctx context.Context, tokenSHA256 []byte, userID int64, expires time.Time) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO sessions (token_sha256, user_id, expires_at) VALUES ($1, $2, $3)`,
		tokenSHA256, userID, expires)
	return mapErr(err)
}

func (s *Store) SessionUser(ctx context.Context, tokenSHA256 []byte) (User, error) {
	return scanUser(s.pool.QueryRow(ctx, `
		SELECT `+userCols+`
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_sha256 = $1 AND s.expires_at > now() AND NOT u.disabled`, tokenSHA256))
}

func (s *Store) DeleteSession(ctx context.Context, tokenSHA256 []byte) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE token_sha256 = $1`, tokenSHA256)
	return mapErr(err)
}

func (s *Store) PurgeSessions(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at <= now()`)
	return tag.RowsAffected(), mapErr(err)
}

func (s *Store) CreateToken(ctx context.Context, tokenSHA256 []byte, userID int64, label string) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx,
		`INSERT INTO api_tokens (token_sha256, user_id, label) VALUES ($1, $2, $3) RETURNING id`,
		tokenSHA256, userID, label).Scan(&id)
	return id, mapErr(err)
}

func (s *Store) Tokens(ctx context.Context) ([]APIToken, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT t.id, t.user_id, u.username, t.label, t.created_at, t.last_used_at, t.revoked
		FROM api_tokens t JOIN users u ON u.id = t.user_id
		ORDER BY t.id`)
	return collect(rows, err, func(r pgx.Row) (APIToken, error) {
		var t APIToken
		err := r.Scan(&t.ID, &t.UserID, &t.Username, &t.Label, &t.CreatedAt, &t.LastUsedAt, &t.Revoked)
		return t, err
	})
}

func (s *Store) RevokeToken(ctx context.Context, id int64) error {
	return affected(s.pool.Exec(ctx, `UPDATE api_tokens SET revoked = true WHERE id = $1`, id))
}

func (s *Store) TokenUser(ctx context.Context, tokenSHA256 []byte) (User, error) {
	return scanUser(s.pool.QueryRow(ctx, `
		UPDATE api_tokens t SET last_used_at = now()
		FROM users u
		WHERE t.token_sha256 = $1 AND NOT t.revoked AND u.id = t.user_id AND NOT u.disabled
		RETURNING `+userCols, tokenSHA256))
}
