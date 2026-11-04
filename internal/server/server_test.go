package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/go-chi/chi/v5"
)

func TestUnifiedServerSubSPARouting(t *testing.T) {
	adminFS := fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<html><body>Admin Console</body></html>")},
	}
	userFS := fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<html><body>Developer Portal</body></html>")},
	}

	s := &Server{
		adminFS: adminFS,
		userFS:  userFS,
	}

	r := chi.NewRouter()

	// 1. API mock
	r.Get("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok"}`))
	})

	// 2. SubSPA for portal
	s.setupSubSPA(r, "/portal", userFS)
	r.Get("/developer", func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "/portal", http.StatusMovedPermanently)
	})

	// 3. Admin SPA
	s.setupSPA(r, adminFS)

	// Test A: GET /
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "Admin Console") {
		t.Errorf("expected Admin Console at /, got %q", rec.Body.String())
	}

	// Test B: GET /domains (Admin SPA routing)
	req = httptest.NewRequest("GET", "/domains", nil)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "Admin Console") {
		t.Errorf("expected Admin Console at /domains, got %q", rec.Body.String())
	}

	// Test C: GET /portal (Developer Portal)
	req = httptest.NewRequest("GET", "/portal", nil)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	t.Logf("GET /portal -> code: %d, headers: %v, body: %q", rec.Code, rec.Header(), rec.Body.String())
	if !strings.Contains(rec.Body.String(), "Developer Portal") {
		t.Errorf("expected Developer Portal at /portal, got %q", rec.Body.String())
	}

	// Test D: GET /developer (Redirect to /portal)
	req = httptest.NewRequest("GET", "/developer", nil)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "/portal" {
		t.Errorf("expected redirect to /portal at /developer, got code %d, loc %q", rec.Code, rec.Header().Get("Location"))
	}

	// Test E: GET /api/health
	req = httptest.NewRequest("GET", "/api/health", nil)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	body, _ := io.ReadAll(rec.Body)
	if string(body) != `{"status":"ok"}` {
		t.Errorf("expected api health response, got %q", string(body))
	}
}
