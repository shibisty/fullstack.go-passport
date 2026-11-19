# Changelog

## Unreleased

## 0.2.0 — 2026-11-19

### Changed
- Renamed from `fullstack-passport` to `@fullstack/passport` (gtr ADR-0012): `gtr add @fullstack/passport`, `import "fullstack/passport"`; published to the gtr registry. Dependencies on fullstack, passport, orm and migration packages are registry ranges instead of `github:` sources.

### Added
- `CSRFField` and `CSRFToken` write a masked token, different on every page (passport's
  `httpauth.CSRFToken`), so compressed pages do not leak it.
- `auth.Provider`: builds the `passport.Authenticator` from strategies, a session store (in
  memory by default, with a warning outside local/testing) and a JWT issuer from
  `AUTH_JWT_SECRET`; registers `*auth.Auth` and `*passport.Authenticator` in the container.
  `Config` from `AUTH_SESSION_TTL`, `AUTH_TOKEN_TTL`, `AUTH_JWT_SECRET`, `AUTH_JWT_ISSUER`,
  `AUTH_LOGIN_PATH`, `AUTH_HOME_PATH`.
- Middleware: `Web` (session cookie), `API` (Bearer token only), `Any`, `Require(guards...)`
  (browsers redirected to the login page with `?redirect=`, others 401 through the router's error
  handler), `Guest`, `CSRF`, `Throttle(max, window)` / `ThrottleWith` for login attempts.
- Helpers: `Login` (a session planted before login is ended), `Logout`, `Attempt`, `IssueToken`,
  `Intended` (only local paths, no open redirects), `Redirect` / `Callback` for OAuth strategies
  (state checked, provider errors as 401); `User`, `Check`, `Guard`, `CSRFToken`, `CSRFField`.
