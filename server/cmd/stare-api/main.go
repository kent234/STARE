package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"stare/server/scanner"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

var db *pgxpool.Pool
var rdb *redis.Client

type ScanRequest struct {
	Target string `json:"target"`
}

type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

// Регистрация
func registerHandler(w http.ResponseWriter, r *http.Request) {
	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	var success bool
	err := db.QueryRow(r.Context(), "SELECT register_user($1, $2)", req.Username, req.Password).Scan(&success)
	if err != nil {
		log.Printf("[DB ERROR] %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if !success {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "registered"})
}

// Логин
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	var success bool
	err := db.QueryRow(r.Context(), "SELECT login_user($1, $2)", req.Username, req.Password).Scan(&success)
	if err != nil || !success {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"token": "stare-secret-token-123"})
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	json.NewDecoder(r.Body).Decode(&req)
	log.Printf("[API] Scan started: %s", req.Target)

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	cachedData, err := rdb.Get(ctx, "scan:"+req.Target).Result()
	if err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(cachedData))
		return
	}

	result := scanner.RunFullScan(ctx, req.Target)
	resultJSON, _ := json.Marshal(result)

	_, err = db.Exec(ctx, "INSERT INTO scans (target, result) VALUES ($1, $2)", req.Target, resultJSON)
	rdb.Set(ctx, "scan:"+req.Target, resultJSON, 10*time.Minute)

	w.Header().Set("Content-Type", "application/json")
	w.Write(resultJSON)
}

func listScansHandler(w http.ResponseWriter, r *http.Request) {
	rows, _ := db.Query(r.Context(), "SELECT id, target, created_at FROM scans ORDER BY created_at DESC LIMIT 20")
	defer rows.Close()

	var scans []map[string]interface{}
	for rows.Next() {
		var id, target string
		var createdAt time.Time
		rows.Scan(&id, &target, &createdAt)
		scans = append(scans, map[string]interface{}{"id": id, "target": target, "created_at": createdAt})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func getScanHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	var resultJSON string
	err := db.QueryRow(r.Context(), "SELECT result FROM scans WHERE id = $1", id).Scan(&resultJSON)
	if err != nil {
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(resultJSON))
}

func main() {
	connStr := fmt.Sprintf("postgres://%s:%s@%s:5432/%s",
		os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_HOST"), os.Getenv("DB_NAME"))
	db, _ = pgxpool.New(context.Background(), connStr)
	rdb = redis.NewClient(&redis.Options{Addr: os.Getenv("REDIS_HOST") + ":6379"})

	http.HandleFunc("/api/scan", corsMiddleware(scanHandler))
	http.HandleFunc("/api/scans", corsMiddleware(listScansHandler))
	http.HandleFunc("/api/scan/get", corsMiddleware(getScanHandler))
	http.HandleFunc("/api/auth/register", corsMiddleware(registerHandler))
	http.HandleFunc("/api/auth/login", corsMiddleware(loginHandler))

	fmt.Println("🚀 API запущен на :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
