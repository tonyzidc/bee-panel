package api

import (
	"encoding/json"
	"net/http"

	"bee-panel/internal/server/middleware"
	"bee-panel/internal/storage"
)

type SetupHandler struct {
	db             *storage.DB
	jwtSecret      string
	jwtExpiryHours int
}

func NewSetupHandler(db *storage.DB, jwtSecret string, jwtExpiryHours int) *SetupHandler {
	return &SetupHandler{
		db:             db,
		jwtSecret:      jwtSecret,
		jwtExpiryHours: jwtExpiryHours,
	}
}

type SetupStatusResponse struct {
	IsSetup bool `json:"is_setup"`
}

type RegisterAdminRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

type AuthResponse struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

// GetStatus checks if the system has completed initial setup
func (h *SetupHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	isSetup, err := h.db.IsSetupCompleted()
	if err != nil {
		http.Error(w, `{"error":"internal database error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(SetupStatusResponse{IsSetup: isSetup})
}

// RegisterInitialAdmin creates the first administrator account
func (h *SetupHandler) RegisterInitialAdmin(w http.ResponseWriter, r *http.Request) {
	isSetup, err := h.db.IsSetupCompleted()
	if err != nil {
		http.Error(w, `{"error":"internal database error"}`, http.StatusInternalServerError)
		return
	}
	if isSetup {
		http.Error(w, `{"error":"setup already completed"}`, http.StatusForbidden)
		return
	}

	var req RegisterAdminRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request payload"}`, http.StatusBadRequest)
		return
	}

	if req.Username == "" || len(req.Password) < 8 {
		http.Error(w, `{"error":"username required and password must be at least 8 characters"}`, http.StatusBadRequest)
		return
	}
	if req.Email == "" {
		req.Email = req.Username + "@bee-panel.local"
	}

	if err := h.db.CreateAdmin(req.Username, req.Password, req.Email); err != nil {
		http.Error(w, `{"error":"failed to create admin: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	admin, err := h.db.AuthenticateAdmin(req.Username, req.Password)
	if err != nil {
		http.Error(w, `{"error":"failed to load created admin"}`, http.StatusInternalServerError)
		return
	}

	token, err := middleware.GenerateToken(admin.ID, admin.Username, "admin", h.jwtSecret, h.jwtExpiryHours)
	if err != nil {
		http.Error(w, `{"error":"failed to issue auth token"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(AuthResponse{
		Token:    token,
		Username: admin.Username,
		Email:    admin.Email,
	})
}
