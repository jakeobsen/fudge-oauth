# fudge-oauth

The sign-in server for [Fudge](https://github.com/jakeobsen/fudge), the Raycast-compatible keyboard launcher for macOS.

Many Raycast extensions sign in to services such as GitHub, Linear or Slack with OAuth. Signing in needs an OAuth app registered with each service, and that app's client secret can't ship inside an app everyone downloads. fudge-oauth holds the OAuth apps and their secrets, and Fudge signs in through it. Run your own for your company, or use Fudge's.

It keeps nothing: no database and no sessions. What a sign-in needs between steps travels encrypted in the OAuth `state` and `code`. It never logs a code, token, secret or verifier.

## Services

The seven that `@raycast/utils`' `OAuthService` has built in:

| Service | Path | Where to register the OAuth app |
|---|---|---|
| GitHub | `github` | GitHub → Settings → Developer settings → OAuth Apps |
| Linear | `linear` | Linear → Settings → API → OAuth applications |
| Slack | `slack` | api.slack.com/apps → your app → OAuth & Permissions → Redirect URLs |
| Asana | `asana` | Asana developer console → your app → OAuth → Redirect URLs |
| Google | `google` | Google Cloud console → APIs & Services → Credentials → OAuth client ID (Web application) → Authorized redirect URIs |
| Jira | `jira` | developer.atlassian.com → Developer console → your app → Authorization → OAuth 2.0 (3LO) → Callback URL |
| Zoom | `zoom` | Zoom App Marketplace → Develop → your app → OAuth Redirect URL, and the OAuth allow list |

Configure only the ones you want to offer.

## Setting it up

1. **Choose its address**, e.g. `https://oauth.example.com`. That's `public_url`. fudge-oauth serves plain HTTP on port 8080; put it behind a proxy that terminates TLS at that address.
2. **Register an OAuth app with each service** you offer. Its callback (redirect) URL is `<public_url>/<path>/callback`, e.g. `https://oauth.example.com/github/callback`. Note the client ID and client secret. Give the app the scopes your extensions ask for; for Slack, those are **user** token scopes.
3. **Make a key** for sealing sign-ins: `openssl rand -base64 32`. Keep it with the secrets. Changing it only interrupts sign-ins in progress.
4. **Configure and start it** (below). The front page, `<public_url>/`, lists the services it offers and each one's callback URL.
5. **In Fudge**, open Settings → Sign-in, choose **Your own server…**, and enter `public_url`.

### With Docker Compose

`docker-compose.yml` is an example. Copy `fudge-oauth.example.yaml` to `fudge-oauth.yaml` and edit it, put the key and each client secret in a file under `secrets/`, then:

```sh
docker compose up -d
```

### With Docker

```sh
docker build -t fudge-oauth .
docker run -d -p 127.0.0.1:8080:8080 \
  -e FUDGE_OAUTH_PUBLIC_URL=https://oauth.example.com \
  -e FUDGE_OAUTH_KEY_FILE=/run/secrets/key \
  -e FUDGE_OAUTH_GITHUB_CLIENT_ID=… \
  -e FUDGE_OAUTH_GITHUB_CLIENT_SECRET_FILE=/run/secrets/github \
  -v "$PWD/secrets:/run/secrets:ro" \
  fudge-oauth
```

The image is a static binary on distroless, running as a non-root user. Its health check runs `/fudge-oauth healthcheck`.

### Without a container

With Go 1.26 or later: `make build`, then run `./fudge-oauth` with the configuration below.

## Configuration

A YAML file, whose path is in `FUDGE_OAUTH_CONFIG`, and environment variables. A variable overrides the file's value. Any secret can come from a file instead (`key_file`, `client_secret_file`), for Docker or Kubernetes secrets; the file's surrounding whitespace is ignored.

| File | Variable | |
|---|---|---|
| `public_url` | `FUDGE_OAUTH_PUBLIC_URL` | Required. The address browsers and Fudge use. `https://`, or `http://` on localhost for testing. |
| `key` / `key_file` | `FUDGE_OAUTH_KEY` / `FUDGE_OAUTH_KEY_FILE` | Required. 32 random bytes in base64. |
| `listen` | `FUDGE_OAUTH_LISTEN` | The address to listen on. Default `:8080`. |
| `providers.<path>.client_id` | `FUDGE_OAUTH_<PATH>_CLIENT_ID` | The OAuth app's client ID. |
| `providers.<path>.client_secret` / `client_secret_file` | `FUDGE_OAUTH_<PATH>_CLIENT_SECRET` / `…_CLIENT_SECRET_FILE` | Its secret. |
| `providers.<path>.authorize_url` | `FUDGE_OAUTH_<PATH>_AUTHORIZE_URL` | Optional: another authorize endpoint, e.g. GitHub Enterprise Server's. |
| `providers.<path>.token_url` | `FUDGE_OAUTH_<PATH>_TOKEN_URL` | Optional: another token endpoint. |
| `providers.<path>.pkce` | `FUDGE_OAUTH_<PATH>_PKCE` | Optional: `true` or `false`, whether fudge-oauth uses PKCE with the service too. |

`<PATH>` is the path in capitals, e.g. `FUDGE_OAUTH_GITHUB_CLIENT_ID`. A service is offered once it has a client ID and secret, and fudge-oauth won't start with none. Unknown settings in the file are errors.

`fudge-oauth.example.yaml` shows a complete file.

## How a sign-in works

fudge-oauth answers at the same paths as Raycast's sign-in servers, and Fudge sends extensions' sign-ins there:

1. `GET /<path>/authorize`: Fudge opens this in the browser, with a PKCE challenge and a redirect back to Fudge on `127.0.0.1` or `[::1]` (nothing else is accepted). fudge-oauth seals those into the `state` and sends the browser to the service with its own client ID. Where the service supports PKCE, fudge-oauth uses its own verifier with it, which rides inside the sealed state and code.
2. `GET /<path>/callback`: the service comes back here. fudge-oauth seals the service's code, and sends the browser back to Fudge with it.
3. `POST /<path>/token`: Fudge exchanges that code, proving with the PKCE verifier that it started the sign-in. fudge-oauth exchanges the service's code with its secret and returns the tokens.
4. `POST /<path>/refresh-token`: refreshes a token the same way. `/token` takes a refresh too, since that's where Google, Jira and Zoom refresh. GitHub's OAuth apps issue no refresh tokens, so GitHub answers 400.

Sealed values are bound to their kind and service: a state never works as a code, nor at another service's paths. A sealed state lasts 10 minutes, a sealed code 5. `GET /healthz` answers 200.

Anyone holding a refresh token can refresh it through fudge-oauth, as with any OAuth proxy; rate limiting, if you want it, belongs in the proxy in front.

Logs are JSON lines on standard output, one per request: the path, the service, the status and the time.

## Development

```sh
make test    # go test -race ./...
make lint    # gofmt, go vet, staticcheck
make image   # docker build
```

## License

Copyright (C) 2026 Morten Jakobsen.

Licensed under the GNU Affero General Public License, version 3 or (at your option) any later version (`AGPL-3.0-or-later`). See [LICENSE](LICENSE).
