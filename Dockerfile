# fudge-oauth: just the static binary and the CA certificates, FROM scratch, as a non-root user.
# It serves plain HTTP on 8080 behind a TLS proxy, or HTTPS on 8443 with its own certificate.

# The build runs on the builder's own platform and cross-compiles, so an arm64 image needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/fudge-oauth ./cmd/fudge-oauth

FROM scratch
# The relay calls the services' token endpoints over HTTPS, so it needs the CA certificates; `healthcheck` fails
# without them. It needs no time zone data: it only compares and logs times, in UTC.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/fudge-oauth /fudge-oauth
# scratch has no /etc/passwd, so the user is a number: 65532, distroless's "nonroot", as before.
USER 65532:65532
EXPOSE 8080 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s CMD ["/fudge-oauth", "healthcheck"]
ENTRYPOINT ["/fudge-oauth"]
