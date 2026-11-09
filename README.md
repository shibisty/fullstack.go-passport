# fullstack-passport

[passport](https://github.com/shibisty/passport.go) for [fullstack](https://github.com/shibisty/fullstack.go):
a service provider, guards as in Laravel (`web`, `api`), the `auth`, `guest`, CSRF and login
throttling middleware, and helpers to log in and out.

## Installation

```json
{
    "dependencies": {
        "fullstack": "github:shibisty/fullstack.go",
        "fullstack-passport": "github:shibisty/fullstack.go-passport",
        "passport": "github:shibisty/passport.go",
        "passport-local": "github:shibisty/passport.go-local-strategy"
    }
}
```

```go
import auth "fullstack-passport" // package auth
```

## Setup

```go
app.Register(&auth.Provider{
    Strategies: []passport.Strategy{local.New(users.Verify)},
    Sessions:   filestore.New("storage/sessions"), // or the redis / sql session stores; nil: in memory
})
au := fullstack.MustMake[*auth.Auth](app)
```

| Variable | Default | |
|---|---|---|
| `AUTH_SESSION_TTL` | `2h` | session lifetime |
| `AUTH_TOKEN_TTL` | `15m` | Bearer token lifetime |
| `AUTH_JWT_SECRET` | — | 32+ bytes; enables Bearer tokens (`IssueToken`, the api guard) |
| `AUTH_JWT_ISSUER` | `fullstack` | |
| `AUTH_LOGIN_PATH` | `/login` | where `Require` sends browsers |
| `AUTH_HOME_PATH` | `/` | where `Guest` sends logged-in users |

`Provider.Configure` gets the `*passport.Authenticator` for anything else; `Provider.Tokens` replaces
the JWT issuer.

## Routes

```go
r := app.Router
r.Group("/", func(site *web.Router) {
    site.Use(au.Web(), au.CSRF()) // the session cookie identifies the user; forms need the CSRF token

    site.Get("/login", showLogin, au.Guest())
    site.Post("/login", func(c *web.Ctx) error {
        _, err := au.Attempt(c, "local", map[string]string{
            "email": c.R.FormValue("email"), "password": c.R.FormValue("password"),
        })
        if errors.Is(err, auth.ErrInvalidCredentials) {
            return c.HTML(422, "pages/login", map[string]any{"Error": "These credentials do not match our records."})
        }
        if err != nil {
            return err
        }
        return c.Redirect(0, au.Intended(c, "/dashboard")) // back to the page Require came from
    }, au.Throttle(5, time.Minute))
    site.Post("/logout", func(c *web.Ctx) error {
        au.Logout(c)
        return c.Redirect(0, "/")
    })
    site.Get("/dashboard", dashboard, au.Require())
})

r.Group("/api", func(api *web.Router) {
    api.Use(au.API()) // Bearer tokens only: a browser's cookie never authenticates an API call
    api.Get("/me", func(c *web.Ctx) error {
        user, _ := auth.User(c)
        return c.JSON(200, user)
    }, au.Require())
})
```

| Middleware | |
|---|---|
| `au.Web()` | identifies the user by the session cookie (guard `web`) |
| `au.API()` | by `Authorization: Bearer` only (guard `api`) |
| `au.Any()` | by either |
| `au.Require(guards...)` | only identified users (of those guards): a browser GET goes to `AUTH_LOGIN_PATH?redirect=…`, everything else is 401 through the router's error handler (JSON for API clients) |
| `au.Guest()` | only visitors: logged-in users go to `AUTH_HOME_PATH` |
| `au.CSRF()` | double-submit CSRF token on POST/PUT/PATCH/DELETE (Bearer requests are not checked) |
| `au.Throttle(max, window)` | login attempts per IP and email/username; 429 with `Retry-After` |

In templates, put `auth.CSRFField(c)` into forms (`{{.CSRFField}}`); JavaScript sends the
`csrf_token` cookie's value in `X-CSRF-Token`.

## Helpers

| | |
|---|---|
| `au.Attempt(c, strategy, creds)` | check credentials and log in; `auth.ErrInvalidCredentials` when wrong |
| `au.Login(c, identity)` / `au.Logout(c)` | start / end the session; a session id planted before login is not reused |
| `au.IssueToken(ctx, identity)` | a Bearer token (needs `AUTH_JWT_SECRET`) |
| `au.Intended(c, fallback)` | the `?redirect=` path, only when it is local (no open redirects) |
| `au.Redirect(c, "google")` / `au.Callback(c, "google")` | OAuth login: state cookie, provider redirect, callback check, login |
| `auth.User(c)`, `auth.Check(c)`, `auth.Guard(c)` | the identified user and how |
| `auth.CSRFToken(c)`, `auth.CSRFField(c)` | the CSRF token, as a value or a hidden input |

## License

MIT
