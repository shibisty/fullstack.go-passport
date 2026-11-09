package auth

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fullstack"
	"fullstack/web"
	"passport"
	"passport/httpauth"
	"passport/memorystore"
)

// password is a credential strategy for tests: ann@example.com / secret.
type password struct{}

func (password) Name() string { return "local" }
func (password) Authenticate(_ context.Context, c map[string]string) (*passport.Identity, error) {
	if c["email"] == "ann@example.com" && c["password"] == "secret" {
		return &passport.Identity{Provider: "local", ProviderUserID: "1", Email: "ann@example.com", Name: "Ann"}, nil
	}
	return nil, passport.ErrInvalidCredentials
}

// oauth is a redirect strategy for tests.
type oauth struct{}

func (oauth) Name() string                    { return "acme" }
func (oauth) AuthCodeURL(state string) string { return "https://acme.test/auth?state=" + state }
func (oauth) Callback(_ context.Context, p map[string]string) (*passport.Identity, error) {
	if p["code"] != "good" {
		return nil, errors.New("bad code")
	}
	return &passport.Identity{Provider: "acme", ProviderUserID: "42", Name: "Acme User"}, nil
}

func clearEnv(t *testing.T) {
	for _, k := range []string{"APP_ENV", "AUTH_SESSION_TTL", "AUTH_TOKEN_TTL", "AUTH_JWT_SECRET", "AUTH_JWT_ISSUER", "AUTH_LOGIN_PATH", "AUTH_HOME_PATH"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
}

func newApp(t *testing.T, p *Provider, env ...string) (*fullstack.App, *Auth) {
	t.Helper()
	clearEnv(t)
	f := filepath.Join(t.TempDir(), ".env")
	os.WriteFile(f, []byte(strings.Join(env, "\n")), 0o600)
	app, err := fullstack.New(fullstack.Options{EnvFiles: []string{f}, LogOutput: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Register(p); err != nil {
		t.Fatal(err)
	}
	au, err := fullstack.Make[*Auth](app)
	if err != nil {
		t.Fatal(err)
	}
	return app, au
}

type client struct {
	t   *testing.T
	h   http.Handler
	jar map[string]*http.Cookie
}

func (c *client) do(method, target string, form url.Values, hdr ...string) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, target, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	for _, ck := range c.jar {
		req.AddCookie(ck)
	}
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, req)
	for _, ck := range w.Result().Cookies() {
		if ck.MaxAge < 0 {
			delete(c.jar, ck.Name)
		} else {
			c.jar[ck.Name] = ck
		}
	}
	return w
}

func site(t *testing.T, env ...string) (*client, *Auth) {
	app, au := newApp(t, &Provider{Strategies: []passport.Strategy{password{}, oauth{}}}, env...)
	r := app.Router
	r.Use(au.Web(), au.CSRF())
	r.Get("/login", func(c *web.Ctx) error { return c.Text(200, "login form "+CSRFToken(c)) }, au.Guest())
	r.Post("/login", func(c *web.Ctx) error {
		_, err := au.Attempt(c, "local", map[string]string{"email": c.R.FormValue("email"), "password": c.R.FormValue("password")})
		if errors.Is(err, ErrInvalidCredentials) {
			return web.Error(422, "These credentials do not match our records.")
		}
		if err != nil {
			return err
		}
		return c.Redirect(0, au.Intended(c, ""))
	}, au.Throttle(3, time.Minute))
	r.Post("/logout", func(c *web.Ctx) error {
		if err := au.Logout(c); err != nil {
			return err
		}
		return c.Redirect(0, "/")
	})
	r.Get("/dashboard", func(c *web.Ctx) error {
		u, _ := User(c)
		return c.Text(200, "hello "+u.Name+" via "+Guard(c)+" "+string(CSRFField(c)))
	}, au.Require())
	r.Get("/web-only", func(c *web.Ctx) error { return c.Text(200, "web") }, au.Require(GuardWeb))
	r.Get("/auth/acme", func(c *web.Ctx) error { return au.Redirect(c, "acme") })
	r.Get("/auth/acme/callback", func(c *web.Ctx) error {
		if _, err := au.Callback(c, "acme"); err != nil {
			return err
		}
		return c.Redirect(0, "/dashboard")
	})
	h, err := app.Handler()
	if err != nil {
		t.Fatal(err)
	}
	return &client{t: t, h: h, jar: map[string]*http.Cookie{}}, au
}

func TestLoginFlow(t *testing.T) {
	c, au := site(t, "APP_ENV=testing", "AUTH_SESSION_TTL=1h")
	if au.Config.SessionTTL != time.Hour {
		t.Fatal(au.Config)
	}
	// Not logged in: a browser is sent to the login page, an API client gets 401.
	if w := c.do("GET", "/dashboard?tab=1", nil); w.Code != 302 || w.Header().Get("Location") != "/login?redirect=%2Fdashboard%3Ftab%3D1" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	if w := c.do("GET", "/dashboard", nil, "Accept", "application/json"); w.Code != 401 || !strings.Contains(w.Body.String(), "Unauthenticated.") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	w := c.do("GET", "/login", nil)
	token := strings.TrimPrefix(w.Body.String(), "login form ")
	if w.Code != 200 || len(token) < 32 {
		t.Fatalf("%d %q", w.Code, w.Body)
	}
	// Without the CSRF token the POST is refused.
	if w := c.do("POST", "/login", url.Values{"email": {"ann@example.com"}, "password": {"secret"}}); w.Code != 403 {
		t.Fatalf("no csrf: %d", w.Code)
	}
	if w := c.do("POST", "/login", url.Values{"email": {"ann@example.com"}, "password": {"nope"}, "_csrf": {token}}); w.Code != 422 {
		t.Fatalf("wrong password: %d %s", w.Code, w.Body)
	}
	// A session id planted before login is not reused.
	c.jar[httpauth.CookieName] = &http.Cookie{Name: httpauth.CookieName, Value: "planted"}
	w = c.do("POST", "/login?redirect=/dashboard%3Ftab%3D1", url.Values{"email": {"ann@example.com"}, "password": {"secret"}, "_csrf": {token}})
	if w.Code != 303 || w.Header().Get("Location") != "/dashboard?tab=1" {
		t.Fatalf("login: %d %v %s", w.Code, w.Header(), w.Body)
	}
	if c.jar[httpauth.CookieName].Value == "planted" {
		t.Fatal("session fixation")
	}
	if w := c.do("GET", "/dashboard", nil); w.Code != 200 || !strings.HasPrefix(w.Body.String(), "hello Ann via web <input type=\"hidden\" name=\"_csrf\" value=\"m") ||
		strings.Contains(w.Body.String(), token) { // masked anew on every page (BREACH)
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := c.do("GET", "/login", nil); w.Code != 302 || w.Header().Get("Location") != "/" {
		t.Fatalf("guest page while logged in: %d", w.Code)
	}
	if w := c.do("GET", "/web-only", nil); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := c.do("POST", "/logout", url.Values{"_csrf": {token}}); w.Code != 303 {
		t.Fatal(w.Code)
	}
	if w := c.do("GET", "/dashboard", nil); w.Code != 302 {
		t.Fatalf("after logout: %d", w.Code)
	}
}

func TestThrottle(t *testing.T) {
	c, _ := site(t, "APP_ENV=testing")
	w := c.do("GET", "/login", nil)
	token := strings.TrimPrefix(w.Body.String(), "login form ")
	bad := url.Values{"email": {"Ann@Example.com "}, "password": {"x"}, "_csrf": {token}}
	for i := 0; i < 3; i++ {
		if w := c.do("POST", "/login", bad); w.Code != 422 {
			t.Fatal(i, w.Code)
		}
	}
	bad.Set("email", "ann@example.com") // the same key, normalized
	if w := c.do("POST", "/login", bad); w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("%d", w.Code)
	}
	bad.Del("email")
	bad.Set("username", "bob") // another key
	if w := c.do("POST", "/login", bad); w.Code != 422 {
		t.Fatal(w.Code)
	}
}

func TestOAuth(t *testing.T) {
	c, _ := site(t, "APP_ENV=testing")
	w := c.do("GET", "/auth/acme", nil)
	loc := w.Header().Get("Location")
	if w.Code != 302 || !strings.HasPrefix(loc, "https://acme.test/auth?state=") {
		t.Fatalf("%d %s", w.Code, loc)
	}
	state := strings.TrimPrefix(loc, "https://acme.test/auth?state=")
	if w := c.do("GET", "/auth/acme/callback?code=good&state=wrong", nil); w.Code != 400 {
		t.Fatalf("bad state: %d", w.Code)
	}
	// The state is single-use: start again.
	w = c.do("GET", "/auth/acme", nil)
	state = strings.TrimPrefix(w.Header().Get("Location"), "https://acme.test/auth?state=")
	if w := c.do("GET", "/auth/acme/callback?error=access_denied&state="+state, nil); w.Code != 401 {
		t.Fatalf("cancelled: %d", w.Code)
	}
	w = c.do("GET", "/auth/acme", nil)
	state = strings.TrimPrefix(w.Header().Get("Location"), "https://acme.test/auth?state=")
	if w := c.do("GET", "/auth/acme/callback?code=bad&state="+state, nil); w.Code != 500 {
		t.Fatalf("strategy error: %d", w.Code)
	}
	w = c.do("GET", "/auth/acme", nil)
	state = strings.TrimPrefix(w.Header().Get("Location"), "https://acme.test/auth?state=")
	if w := c.do("GET", "/auth/acme/callback?code=good&state="+state, nil); w.Code != 303 {
		t.Fatalf("callback: %d %s", w.Code, w.Body)
	}
	if w := c.do("GET", "/dashboard", nil); !strings.HasPrefix(w.Body.String(), "hello Acme User") {
		t.Fatalf("%s", w.Body)
	}
}

func TestAPITokens(t *testing.T) {
	secret := strings.Repeat("k", 32)
	app, au := newApp(t, &Provider{Strategies: []passport.Strategy{password{}}}, "AUTH_JWT_SECRET="+secret, "AUTH_TOKEN_TTL=5m", "APP_ENV=testing")
	app.Router.Post("/api/token", func(c *web.Ctx) error {
		id, err := au.Credential(c.Context(), "local", map[string]string{"email": c.R.FormValue("email"), "password": c.R.FormValue("password")})
		if err != nil {
			return web.Wrap(401, err)
		}
		tok, err := au.IssueToken(c.Context(), id)
		if err != nil {
			return err
		}
		return c.Text(200, tok)
	})
	app.Router.Get("/api/me", func(c *web.Ctx) error {
		u, _ := User(c)
		return c.Text(200, u.Email+" "+Guard(c))
	}, au.API(), au.Require())
	app.Router.Get("/any", func(c *web.Ctx) error { return c.Text(200, Guard(c)) }, au.Any(), au.Require(GuardAPI))
	h, _ := app.Handler()
	c := &client{t: t, h: h, jar: map[string]*http.Cookie{}}
	tok := c.do("POST", "/api/token", url.Values{"email": {"ann@example.com"}, "password": {"secret"}}).Body.String()
	if w := c.do("GET", "/api/me", nil, "Authorization", "Bearer "+tok); w.Body.String() != "ann@example.com api" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := c.do("GET", "/api/me", nil, "Authorization", "Bearer nope"); w.Code != 302 && w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := c.do("GET", "/api/me", nil, "Accept", "application/json"); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := c.do("GET", "/any", nil, "Authorization", "Bearer "+tok); w.Body.String() != "api" {
		t.Fatal(w.Body)
	}
	// A session cookie does not pass Require(GuardAPI).
	sid, _ := au.StartSession(context.Background(), &passport.Identity{ProviderUserID: "1"}, time.Minute)
	c.jar[httpauth.CookieName] = &http.Cookie{Name: httpauth.CookieName, Value: sid}
	if w := c.do("POST", "/any", nil); w.Code != 405 {
		t.Fatal(w.Code)
	}
	if w := c.do("GET", "/any", nil, "Accept", "application/json"); w.Code != 401 {
		t.Fatalf("session on an api route: %d", w.Code)
	}
	if mk, err := fullstack.Make[*passport.Authenticator](app); err != nil || mk != au.Authenticator {
		t.Fatal("Authenticator in the container")
	}
}

func TestProviderOptions(t *testing.T) {
	store := memorystore.New()
	configured := false
	_, au := newApp(t, &Provider{
		Sessions: store,
		Configure: func(app *fullstack.App, a *passport.Authenticator) error {
			configured = true
			return nil
		},
	}, "APP_ENV=production")
	if !configured {
		t.Fatal("Configure not called")
	}
	if _, err := au.StartSession(context.Background(), &passport.Identity{}, time.Minute); err != nil || store.Len() != 1 {
		t.Fatal("custom session store", err)
	}
	if _, err := au.IssueToken(context.Background(), &passport.Identity{}); !errors.Is(err, passport.ErrNoTokenIssuer) {
		t.Fatal("tokens without a secret", err)
	}

	// Errors.
	clearEnv(t)
	app, _ := fullstack.New(fullstack.Options{EnvFiles: []string{}, LogOutput: io.Discard})
	t.Setenv("AUTH_JWT_SECRET", "short")
	app.Register(&Provider{})
	if _, err := fullstack.Make[*Auth](app); err == nil || !strings.Contains(err.Error(), "AUTH_JWT_SECRET") {
		t.Fatal(err)
	}
	if _, err := fullstack.Make[*passport.Authenticator](app); err == nil {
		t.Fatal("Authenticator built from a broken Auth")
	}
	os.Unsetenv("AUTH_JWT_SECRET")
	app2, _ := fullstack.New(fullstack.Options{EnvFiles: []string{}, LogOutput: io.Discard})
	app2.Register(&Provider{Configure: func(*fullstack.App, *passport.Authenticator) error { return errors.New("nope") }})
	if _, err := fullstack.Make[*Auth](app2); err == nil {
		t.Fatal("Configure error")
	}
	t.Setenv("AUTH_SESSION_TTL", "soon")
	app3, _ := fullstack.New(fullstack.Options{EnvFiles: []string{}, LogOutput: io.Discard})
	if err := app3.Register(&Provider{}); err == nil {
		t.Fatal("bad AUTH_SESSION_TTL")
	}
	n := New(passport.New(), Config{})
	if n.Config.SessionTTL != 2*time.Hour || n.Config.LoginPath != "/login" || n.Config.HomePath != "/" || n.Config.TokenTTL != 15*time.Minute {
		t.Fatal(n.Config)
	}
}

func TestIntendedAndHelpers(t *testing.T) {
	au := New(passport.New().UseSessionStore(memorystore.New()), Config{HomePath: "/home"})
	r := web.NewRouter()
	r.SetLogger(fullstackDiscard())
	r.Get("/i", func(c *web.Ctx) error { return c.Text(200, au.Intended(c, "")) })
	r.Get("/u", func(c *web.Ctx) error {
		if Check(c) || Guard(c) != "" || CSRFToken(c) != "" {
			return errors.New("visitor expected")
		}
		return au.Logout(c) // no session: nothing to end
	})
	for q, want := range map[string]string{
		"":                       "/home",
		"?redirect=/a?b=1":       "/a?b=1",
		"?redirect=//evil.com":   "/home",
		"?redirect=https://evil": "/home",
		"?redirect=/%5Cevil.com": "/home",
		"?redirect=/a%0d%0aX":    "/home",
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", "/i"+q, nil))
		if w.Body.String() != want {
			t.Errorf("%s: %q", q, w.Body)
		}
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/u", nil))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	// Redirect with an unknown strategy is an error.
	r.Get("/r", func(c *web.Ctx) error { return au.Redirect(c, "nope") })
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/r", nil))
	if w.Code != 500 {
		t.Fatal(w.Code)
	}
	// Login fails when the store fails.
	broken := New(passport.New().UseSessionStore(failingStore{}), Config{})
	r.Get("/l", func(c *web.Ctx) error { return broken.Login(c, &passport.Identity{}) })
	r.Get("/a", func(c *web.Ctx) error {
		_, err := broken.Attempt(c, "missing", nil)
		return err
	})
	for _, p := range []string{"/l", "/a"} {
		w = httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", p, nil))
		if w.Code != 500 {
			t.Fatal(p, w.Code)
		}
	}
	// Guest without a user passes.
	g := au.Guest()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	w = httptest.NewRecorder()
	g.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 204 {
		t.Fatal(w.Code)
	}
	// A JSON POST to a protected route is a 401, not a redirect.
	req := httptest.NewRequest("POST", "/", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	au.Require()(g).ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
}

type failingStore struct{}

func (failingStore) Create(context.Context, *passport.Identity, time.Duration) (string, error) {
	return "", errors.New("store down")
}
func (failingStore) Get(context.Context, string) (*passport.Identity, error) {
	return nil, passport.ErrSessionNotFound
}
func (failingStore) Destroy(context.Context, string) error { return nil }

func fullstackDiscard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
