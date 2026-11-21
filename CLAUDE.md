# CLAUDE.md

Guidance for AI coding agents working in this repository. User-facing docs are in README.md.

## What this is

fudge-oauth is the OAuth sign-in relay for Fudge (`jakeobsen/fudge`), a macOS launcher that runs Raycast extensions. Extensions sign in through `@raycast/utils`' `OAuthService`, which talks to Raycast's proxies (`https://<provider>.oauth.raycast.com/{authorize,token,refresh-token}`) for GitHub, Linear, Slack and Asana, and to the provider for Google, Jira and Zoom. Fudge sends all seven to `<relay>/<provider>/{authorize,token,refresh-token}` instead. The relay holds the OAuth apps' client secrets; Fudge holds none.

## Layout

- `cmd/fudge-oauth`: `main`. Loads the config, serves with timeouts and a graceful shutdown on SIGTERM, and has a `healthcheck [URL]` subcommand for the container's health check (distroless has no shell or curl).
- `internal/provider`: the built-in table, one `Provider` per provider: path name, title, endpoints, whether the relay uses PKCE with it, whether it issues refresh tokens, how client credentials go (`ClientAuthBody` or `ClientAuthBasic`) and the token body encoding (`BodyForm` or `BodyJSON`).
- `internal/config`: `Load(getenv, readFile)`. YAML from `FUDGE_OAUTH_CONFIG` (strict: unknown fields are errors), then `FUDGE_OAUTH_*` variables override value by value, then validation. Secrets may come from files (`key_file`, `client_secret_file`), trimmed. A provider is configured once it has a client ID and secret.
- `internal/seal`: AES-256-GCM sealing. The expiry is inside the ciphertext, and the purpose is the additional data. The relay's purposes are `state/<provider>` and `code/<provider>` (`purpose` in `relay.go`), so a sealed state never opens as a code, nor either at another provider's endpoints. Output is unpadded base64url.
- `internal/relay`: the HTTP handlers (`relay.go`), the token exchange with the provider (`exchange.go`), and the pages and request logging (`pages.go`).

## The flow

- **authorize** checks `redirect_uri` is `http://127.0.0.1:<port>/…` or `http://[::1]:<port>/…` (`LoopbackRedirect`), and requires an S256 `code_challenge` and a `state`. It seals Fudge's redirect, state and challenge, plus the relay's own PKCE verifier when the provider uses PKCE, into the provider's `state` (10 minutes). It redirects with the relay's `client_id` and callback; every other incoming parameter goes on unchanged (Linear's `actor`, Slack's `user_scope`, Google's `access_type`, Jira's `audience`). An empty `scope` is left out, since `OAuthService.slack` sends one.
- **callback** opens the sealed state, then redirects to Fudge's redirect with Fudge's `state` and a sealed code (provider, provider's code, Fudge's redirect and challenge, the relay's verifier; 5 minutes), or with the provider's `error`. A state that won't open gets an HTML page, never a redirect.
- **token** accepts JSON or form bodies, exactly as `OAuthService.fetchTokens` sends them. It opens the code, checks the provider, the `redirect_uri` if sent, and `S256(code_verifier)` against the sealed challenge, before anything reaches the provider. The incoming `client_id` is the extension's and is ignored.
- **refresh-token** forwards a refresh grant, or answers 400 `unsupported_grant_type` for a provider without refresh tokens (GitHub). **token** takes a refresh grant too, since `OAuthService` refreshes Google, Jira and Zoom at their token URL.
- **The relay's own parameters can't be overridden.** `ownParams` keeps `client_id`, `redirect_uri`, `state`, `response_type`, `scope` and the PKCE parameters out of what passes through to the provider; the relay sets each itself (PKCE only where the provider uses it).
- **The exchange** asks for JSON (`Accept`), since GitHub answers form-encoded otherwise, and still reads a form-encoded answer (expiry times become numbers). It never follows a redirect. GitHub and Slack report errors with a 200 (`{"error": …}`, `{"ok": false}`), so `isProviderError` checks the body. A provider's refusal is a 400 with its `error`; a failure, an unreadable answer or a redirect is a 502 `temporarily_unavailable`. A success passes the provider's JSON through unchanged: `OAuthService.slack`'s default `tokenResponseParser` reads `authed_user.access_token`, and Linear's array `scope` is normalised by `OAuthService` itself.

## Rules

- **Never log secrets.** Request logs carry only the path (never the query), the provider, the status and the duration. Other log lines carry the provider and an upstream status. Never log a body, a query string, a header, an error that might quote one, or a config value other than the listen address, public URL and provider names. `checkLogs` in the tests greps the log for every secret, code, state, verifier and token a test saw; keep it in each new flow test.
- **Nothing is stored.** No database, no cache, no sessions. Anything a later step needs goes into a sealed value.
- Standard library first. The one dependency is `go.yaml.in/yaml/v3`. A new one must be pinned and AGPL-compatible, and clearly worth it.
- Error pages are `html/template`, so a provider name from the path is escaped. Token endpoints answer OAuth-style JSON errors (`error`, `error_description`), which `OAuthService` shows in its error message.
- Conventional commits (`feat: …`, `fix: …`, `test: …`, `ci: …`, `docs: …`).

## Tests

`make test` (`go test -race ./...`) and `make lint` (gofmt, `go vet`, staticcheck pinned in the Makefile). CI runs both on Ubuntu, then builds the image, starts it and checks `/healthz` and the front page.

`internal/relay` tests run the relay against fake providers (`fake_test.go`): `httptest` servers that check each request the way that provider would (client credentials, body encoding, `Accept`, the relay's callback, PKCE) and answer with that provider's documented response shapes, including its error shapes. `relay_test.go` pins what Fudge and `OAuthService` send: the authorize parameters, and the token and refresh bodies field for field, as JSON and as `URLSearchParams`. No test reaches a real provider or the network. Time is a `WithClock` option, so expiry tests advance a fake clock. The harness's `t` is the top-level test's, used only by the fakes from their own goroutines; helpers take the running (sub)test's `t`.
