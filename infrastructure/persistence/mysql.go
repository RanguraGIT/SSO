package persistence

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

func OpenMySQL() (*sql.DB, error) {
	if dsn := os.Getenv("DB_DSN"); dsn != "" {
		logSanitizedDSN(dsn)
		return open(dsn)
	}
	user := getenv("DB_USER", "root")
	pass := getenv("DB_PASS", "root")
	host := getenv("DB_HOST", "127.0.0.1")
	port := getenv("DB_PORT", "3306")
	name := getenv("DB_NAME", "rangura")
	params := "parseTime=true&loc=UTC&charset=utf8mb4,utf8"
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?%s", user, pass, host, port, name, params)
	logSanitizedDSN(dsn)
	return open(dsn)
}

// OpenMySQLCreatingDB attempts to create the database first if it does not exist.
// Useful for test environments where the database may not be pre-created.
func OpenMySQLCreatingDB() (*sql.DB, error) {
	// Build server-level DSN without DB name to issue CREATE DATABASE IF NOT EXISTS
	user := getenv("DB_USER", "root")
	pass := getenv("DB_PASS", "root")
	host := getenv("DB_HOST", "127.0.0.1")
	port := getenv("DB_PORT", "3306")
	name := getenv("DB_NAME", "rangura")
	params := "parseTime=true&loc=UTC&charset=utf8mb4,utf8"
	serverDSN := fmt.Sprintf("%s:%s@tcp(%s:%s)/?%s", user, pass, host, port, params)
	if os.Getenv("LOG_DB_DSN") == "1" {
		logSanitizedDSN(serverDSN)
	}
	server, err := open(serverDSN)
	if err != nil {
		return nil, err
	}
	// Create database if missing
	_, err = server.Exec("CREATE DATABASE IF NOT EXISTS `" + name + "`")
	if err != nil {
		_ = server.Close()
		return nil, err
	}
	_ = server.Close()
	// Now open the real DB
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?%s", user, pass, host, port, name, params)
	return open(dsn)
}

func logSanitizedDSN(dsn string) {
	if os.Getenv("LOG_DB_DSN") != "1" {
		return
	}
	// Basic redaction: split user:pass@tcp(...)
	parts := strings.SplitN(dsn, "@", 2)
	if len(parts) != 2 {
		log.Printf("db: dsn=%s", dsn)
		return
	}
	cred := parts[0]
	after := parts[1]
	user := cred
	if idx := strings.Index(cred, ":"); idx >= 0 {
		user = cred[:idx]
	}
	log.Printf("db: connecting user=%s dsn=***@%s", user, after)
}

func open(dsn string) (*sql.DB, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	// Basic pool tuning; adjust later
	db.SetConnMaxLifetime(55 * time.Minute)
	db.SetMaxIdleConns(5)
	db.SetMaxOpenConns(25)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func getenv(k, def string) string {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	return v
}
