//go:build dynamic_secrets

package dynamicsecret

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib" // register pgx driver with database/sql
)

// sqlExecutor defines the interface for database operations.
// Using database/sql interface for testability.
type sqlExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	Close() error
}

// PostgreSQLEngine generates dynamic PostgreSQL credentials.
type PostgreSQLEngine struct {
	connectionString string
	db               sqlExecutor
	mu               sync.Mutex
	usernames        sync.Map
}

// NewPostgreSQLEngine creates a new PostgreSQL engine.
func NewPostgreSQLEngine(connStr string) *PostgreSQLEngine {
	return &PostgreSQLEngine{connectionString: connStr}
}

// Type returns the engine type identifier.
func (e *PostgreSQLEngine) Type() string {
	return EngineTypePostgres
}

func (e *PostgreSQLEngine) getDB(ctx context.Context) (sqlExecutor, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.db != nil {
		return e.db, nil
	}
	db, err := sql.Open("pgx", e.connectionString)
	if err != nil {
		return nil, fmt.Errorf("postgres: open connection: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	e.db = db
	return e.db, nil
}

// quoteIdentifier safely quotes a PostgreSQL identifier.
func quoteIdentifier(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

// generatePassword generates a cryptographically secure random password.
func generatePassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", fmt.Errorf("generate password: %w", err)
		}
		b[i] = charset[n.Int64()]
	}
	return string(b), nil
}

// generateUsername creates a unique username based on the role.
func generateUsername(role string) string {
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	return role + "_" + hex.EncodeToString(suffix)
}

// Generate creates a temporary PostgreSQL user with a random password.
// The user is granted the specified role and has a TTL-limited validity.
func (e *PostgreSQLEngine) Generate(ctx context.Context, req GenerateRequest) (*Secret, error) {
	if err := e.Validate(ctx, req); err != nil {
		return nil, err
	}

	db, err := e.getDB(ctx)
	if err != nil {
		return nil, err
	}

	username := generateUsername(req.Role)
	password, err := generatePassword(24)
	if err != nil {
		return nil, fmt.Errorf("postgres: %w", err)
	}

	validUntil := time.Now().UTC().Add(req.TTL).Format("2006-01-02 15:04:05Z07:00")

	// Inline the password as a safely quoted string literal instead of using
	// bind parameters. PostgreSQL does not allow DDL statements (CREATE USER)
	// to be prepared via the extended protocol, so bind parameters fail with
	// a parse error. The password charset is alphanumeric, so quoting is safe.
	escapedPassword := strings.ReplaceAll(password, "'", "''")
	createSQL := fmt.Sprintf(
		"CREATE USER %s WITH PASSWORD '%s' VALID UNTIL '%s'",
		quoteIdentifier(username),
		escapedPassword,
		validUntil,
	)
	if _, err := db.ExecContext(ctx, createSQL); err != nil {
		return nil, fmt.Errorf("postgres: create user: %w", err)
	}

	grantSQL := fmt.Sprintf(
		"GRANT %s TO %s",
		quoteIdentifier(req.Role), quoteIdentifier(username),
	)
	if _, err := db.ExecContext(ctx, grantSQL); err != nil {
		dropSQL := fmt.Sprintf("DROP USER IF EXISTS %s", quoteIdentifier(username))
		_, _ = db.ExecContext(context.Background(), dropSQL)
		return nil, fmt.Errorf("postgres: grant role: %w", err)
	}

	leaseID := uuid.New().String()
	e.usernames.Store(leaseID, username)

	return &Secret{
		LeaseID:       leaseID,
		LeaseDuration: req.TTL,
		Renewable:     false,
		CreatedAt:     time.Now().UTC(),
		EngineType:    EngineTypePostgres,
		Data: map[string]any{
			"connection_string": e.connectionString,
			"username":          username,
			"password":          password,
			"role":              req.Role,
		},
	}, nil
}

// Revoke drops the PostgreSQL user associated with the lease ID.
func (e *PostgreSQLEngine) Revoke(ctx context.Context, leaseID string) error {
	db, err := e.getDB(ctx)
	if err != nil {
		return err
	}

	usernameRaw, ok := e.usernames.Load(leaseID)
	if !ok {
		return fmt.Errorf("postgres: lease %q not found", leaseID)
	}
	username, _ := usernameRaw.(string)

	dropSQL := fmt.Sprintf("DROP USER IF EXISTS %s", quoteIdentifier(username))
	if _, err := db.ExecContext(ctx, dropSQL); err != nil {
		return fmt.Errorf("postgres: drop user: %w", err)
	}

	e.usernames.Delete(leaseID)
	return nil
}

// Validate checks that the request parameters are valid for PostgreSQL.
func (e *PostgreSQLEngine) Validate(_ context.Context, req GenerateRequest) error {
	if req.Role == "" {
		return fmt.Errorf("postgres: role is required")
	}
	if req.TTL <= 0 {
		return fmt.Errorf("postgres: TTL must be positive")
	}
	return nil
}
