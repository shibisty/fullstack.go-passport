// Package auth wires passport into fullstack (gtr package fullstack-passport):
// a service provider that builds the passport.Authenticator from the
// configuration, guards and middleware for the router (web, api, auth,
// guest, CSRF, login throttling) and helpers to log in and out.
//
//	app.Register(&auth.Provider{
//	    Strategies: []passport.Strategy{local.New(verifyUser)},
//	    Sessions:   filestore.New("storage/sessions"),
//	})
//	au := fullstack.MustMake[*auth.Auth](app)
//
//	r := app.Router
//	r.Use(au.Web(), au.CSRF())                       // session cookie + CSRF for the site
//	r.Get("/login", showLogin, au.Guest())
//	r.Post("/login", login, au.Throttle(5, time.Minute))
//	r.Get("/dashboard", dashboard, au.Require())
//	r.Group("/api", func(api *web.Router) {
//	    api.Get("/me", me, au.API(), au.Require())  // Bearer token only
//	})
package auth

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"fullstack"
	"fullstack/env"
	"fullstack/web"
	"passport"
	"passport/httpauth"
	"passport/jwt"
	"passport/memorystore"
	"passport/ratelimit"
)

// Config is read from the environment by Provider.
type Config struct {
	SessionTTL time.Duration `env:"AUTH_SESSION_TTL" default:"2h"`
	TokenTTL   time.Duration `env:"AUTH_TOKEN_TTL" default:"15m"`
	// JWTSecret enables Bearer tokens (IssueToken, the api guard); at least
	// 32 bytes. Without it only sessions work.
	JWTSecret string `env:"AUTH_JWT_SECRET"`
	JWTIssuer string `env:"AUTH_JWT_ISSUER" default:"fullstack"`
	// LoginPath is where Require sends browsers that are not logged in;
	// HomePath where Guest sends those who are.
	LoginPath string `env:"AUTH_LOGIN_PATH" default:"/login"`
	HomePath  string `env:"AUTH_HOME_PATH" default:"/"`
}

// Provider registers *Auth and *passport.Authenticator in the container.
type Provider struct {
	// Strategies to register (local, google, apikey…).
	Strategies []passport.Strategy
	// Sessions stores the sessions; nil is an in-memory store, lost on
	// restart and not shared between instances (a warning is logged outside
	// APP_ENV=local and testing).
	Sessions passport.SessionStore
	// Tokens issues Bearer tokens; nil builds a JWT issuer from
	// AUTH_JWT_SECRET when it is set.
	Tokens passport.TokenIssuer
	// Configure runs last, for anything else on the Authenticator.
	Configure func(app *fullstack.App, a *passport.Authenticator) error
}

// Auth is the authentication service: the Authenticator, its configuration
// and the middleware and helpers built on them.
type Auth struct {
	*passport.Authenticator
	Config Config
}

// Register reads Config and provides *Auth and *passport.Authenticator.
func (p *Provider) Register(app *fullstack.App) error {
	var cfg Config
	if err := env.Decode(&cfg); err != nil {
		return err
	}
	fullstack.Provide(app, func(app *fullstack.App) (*Auth, error) { return p.build(app, cfg) })
	fullstack.Provide(app, func(app *fullstack.App) (*passport.Authenticator, error) {
		au, err := fullstack.Make[*Auth](app)
		if err != nil {
			return nil, err
		}
		return au.Authenticator, nil
	})
	return nil
}

func (p *Provider) build(app *fullstack.App, cfg Config) (*Auth, error) {
	a := passport.New()
	for _, s := range p.Strategies {
		a.Use(s)
	}
	sessions := p.Sessions
	if sessions == nil {
		if !app.IsLocal() && !app.IsTesting() {
			app.Log.Warn("auth: sessions are kept in memory; set Provider.Sessions for production")
		}
		sessions = memorystore.New()
	}
	a.UseSessionStore(sessions)
	tokens := p.Tokens
	if tokens == nil && cfg.JWTSecret != "" {
		iss, err := jwt.New(cfg.JWTSecret, cfg.JWTIssuer)
		if err != nil {
			return nil, fmt.Errorf("auth: AUTH_JWT_SECRET: %w", err)
		}
		tokens = iss
	}
	if tokens != nil {
		a.UseTokenIssuer(tokens)
	}
	if p.Configure != nil {
		if err := p.Configure(app, a); err != nil {
			return nil, err
		}
	}
	return &Auth{Authenticator: a, Config: cfg}, nil
}

// New returns an Auth without the container (tests, small programs).
func New(a *passport.Authenticator, cfg Config) *Auth {
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 2 * time.Hour
	}
	if cfg.TokenTTL == 0 {
		cfg.TokenTTL = 15 * time.Minute
	}
	if cfg.LoginPath == "" {
		cfg.LoginPath = "/login"
	}
	if cfg.HomePath == "" {
		cfg.HomePath = "/"
	}
	return &Auth{Authenticator: a, Config: cfg}
}

// ---- Middleware ----

// Web identifies the user by the session cookie (the "web" guard).
func (au *Auth) Web() web.Middleware { return httpauth.Web(au.Authenticator) }

// API identifies the user by an Authorization: Bearer token only (the
// "api" guard): a browser's cookie never authenticates an API call.
func (au *Auth) API() web.Middleware { return httpauth.API(au.Authenticator) }

// Any identifies the user by a Bearer token or the session cookie.
func (au *Auth) Any() web.Middleware { return httpauth.Middleware(au.Authenticator) }

// Require lets only identified users through (Laravel's auth middleware):
// browsers asking for a page (GET, not JSON) are redirected to LoginPath
// with ?redirect=<the page>, others get 401. With guards, the user must
// have been identified by one of them (auth.GuardWeb, auth.GuardAPI).
func (au *Auth) Require(guards ...string) web.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, ok := httpauth.FromContext(r.Context())
			if ok && len(guards) > 0 {
				ok = false
				g := httpauth.GuardFrom(r.Context())
				for _, want := range guards {
					if g == want {
						ok = true
					}
				}
			}
			if ok {
				next.ServeHTTP(w, r)
				return
			}
			if (r.Method == http.MethodGet || r.Method == http.MethodHead) && !wantsJSON(r) && au.Config.LoginPath != "" {
				target := au.Config.LoginPath + "?redirect=" + url.QueryEscape(r.URL.RequestURI())
				http.Redirect(w, r, target, http.StatusFound)
				return
			}
			web.Fail(w, r, web.Error(http.StatusUnauthorized, "Unauthenticated."))
		})
	}
}

// Guest lets only visitors through (login and register pages): logged-in
// users are redirected to HomePath.
func (au *Auth) Guest() web.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := httpauth.FromContext(r.Context()); ok {
				http.Redirect(w, r, au.Config.HomePath, http.StatusFound)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// CSRF is passport's double-submit CSRF check for cookie-authenticated
// routes; put CSRFField(c) into forms.
func (au *Auth) CSRF() web.Middleware { return httpauth.CSRF }

// Throttle limits login attempts per client IP and login field ("email",
// then "username") to max per window; over it the answer is 429 with
// Retry-After. A successful login (a response below 400) resets the count.
func (au *Auth) Throttle(max int, window time.Duration) web.Middleware {
	return ThrottleWith(ratelimit.New(max, window), func(r *http.Request) string {
		login := r.PostFormValue("email")
		if login == "" {
			login = r.PostFormValue("username")
		}
		return httpauth.ClientIP(r) + "|" + strings.ToLower(strings.TrimSpace(login))
	})
}

// ThrottleWith is Throttle with your own limiter (shared, e.g. in Redis)
// and key.
func ThrottleWith(l ratelimit.Limiter, key func(*http.Request) string) web.Middleware {
	return func(next http.Handler) http.Handler { return httpauth.LimitLogin(l, key, next) }
}

func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "json") ||
		strings.HasPrefix(r.Header.Get("Content-Type"), "application/json")
}

// ---- Helpers ----

// Guards, as in Laravel.
const (
	GuardWeb = httpauth.GuardWeb
	GuardAPI = httpauth.GuardAPI
)

// User returns the identified user of the request.
func User(c *web.Ctx) (*passport.Identity, bool) { return httpauth.FromContext(c.Context()) }

// Check reports whether the request has an identified user.
func Check(c *web.Ctx) bool {
	_, ok := User(c)
	return ok
}

// Guard returns the guard that identified the user ("" for a visitor).
func Guard(c *web.Ctx) string { return httpauth.GuardFrom(c.Context()) }

// CSRFToken returns the request's CSRF token (under the CSRF middleware).
func CSRFToken(c *web.Ctx) string { return httpauth.CSRFToken(c.R) }

// CSRFField returns the hidden form input with the CSRF token:
// {{.CSRFField}} in a template.
func CSRFField(c *web.Ctx) template.HTML {
	return template.HTML(`<input type="hidden" name="` + httpauth.CSRFField + `" value="` +
		template.HTMLEscapeString(CSRFToken(c)) + `">`)
}

// Login starts a session for identity and sets the session cookie. A
// session the request already had is ended first, so a session id fixed
// before login is never reused.
func (au *Auth) Login(c *web.Ctx, identity *passport.Identity) error {
	if old, err := c.R.Cookie(httpauth.CookieName); err == nil && old.Value != "" {
		_ = au.EndSession(c.Context(), old.Value)
	}
	id, err := au.StartSession(c.Context(), identity, au.Config.SessionTTL)
	if err != nil {
		return err
	}
	httpauth.SetSessionCookie(c.W, id, int(au.Config.SessionTTL/time.Second))
	return nil
}

// Logout ends the session and clears the cookie.
func (au *Auth) Logout(c *web.Ctx) error {
	httpauth.ClearSessionCookie(c.W)
	if old, err := c.R.Cookie(httpauth.CookieName); err == nil && old.Value != "" {
		return au.EndSession(c.Context(), old.Value)
	}
	return nil
}

// ErrInvalidCredentials is passport's: wrong login or password.
var ErrInvalidCredentials = passport.ErrInvalidCredentials

// Attempt checks credentials with a credential strategy ("local") and logs
// the user in. Wrong credentials are ErrInvalidCredentials, to answer
// without saying which part was wrong.
func (au *Auth) Attempt(c *web.Ctx, strategy string, credentials map[string]string) (*passport.Identity, error) {
	id, err := au.Credential(c.Context(), strategy, credentials)
	if err != nil {
		return nil, err
	}
	return id, au.Login(c, id)
}

// IssueToken issues a Bearer token for identity with TokenTTL.
func (au *Auth) IssueToken(ctx context.Context, identity *passport.Identity) (string, error) {
	return au.Authenticator.IssueToken(ctx, identity, au.Config.TokenTTL)
}

// Intended returns where to go after login: the ?redirect= that Require
// added, when it is a path on this site, otherwise fallback (HomePath when
// empty). Absolute and protocol-relative URLs are refused (open redirects).
func (au *Auth) Intended(c *web.Ctx, fallback string) string {
	if fallback == "" {
		fallback = au.Config.HomePath
	}
	to := c.R.FormValue("redirect")
	if to == "" || !strings.HasPrefix(to, "/") || strings.HasPrefix(to, "//") || strings.HasPrefix(to, "/\\") || strings.ContainsAny(to, "\r\n") {
		return fallback
	}
	return to
}

// Redirect starts a login with a redirect strategy ("google", "github"):
// it sets the state cookie and redirects the browser to the provider.
func (au *Auth) Redirect(c *web.Ctx, strategy string) error {
	state, err := httpauth.NewState(c.W)
	if err != nil {
		return err
	}
	to, err := au.RedirectURL(strategy, state)
	if err != nil {
		return err
	}
	return c.Redirect(http.StatusFound, to)
}

// Callback completes a redirect login: it checks the state (a mismatch is
// a 400), passes the provider's parameters to the strategy and logs the
// user in. A provider error (?error=access_denied) is a 401.
func (au *Auth) Callback(c *web.Ctx, strategy string) (*passport.Identity, error) {
	if err := httpauth.CheckState(c.W, c.R); err != nil {
		return nil, &web.HTTPError{Status: http.StatusBadRequest, Message: "Invalid login state, please try again.", Err: err}
	}
	if e := c.R.FormValue("error"); e != "" {
		return nil, &web.HTTPError{Status: http.StatusUnauthorized, Message: "Login was cancelled.", Err: errors.New(e)}
	}
	params := map[string]string{}
	for k, v := range c.R.Form { // the query, or the body of a form_post callback
		if len(v) > 0 {
			params[k] = v[0]
		}
	}
	id, err := au.Authenticator.Callback(c.Context(), strategy, params)
	if err != nil {
		return nil, err
	}
	return id, au.Login(c, id)
}
