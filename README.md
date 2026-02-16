# external-auth-template

Template / demo implementations of the [EdgeQuota](https://github.com/edgequota/edgequota) external authentication protocol.

EdgeQuota calls an external auth service for every incoming request when authentication is enabled. This repository provides two ready-to-use implementations — one using **gRPC** and one using plain **HTTP** — that demonstrate how to:

1. Validate a JWT Bearer token from the `Authorization` header.
2. Extract a `tenant_id` claim and return it as an `X-Tenant-Id` request header that EdgeQuota injects into the upstream request.
3. Expose a helper endpoint to create JWTs for testing.

## Project structure

```
external-auth-template/
├── grpc/           # gRPC implementation (edgequota.auth.v1.AuthService)
│   ├── main.go     # gRPC server (:50051) + HTTP token endpoint (:8081)
│   ├── auth.go     # AuthService implementation + JWT helpers
│   ├── auth_test.go
│   ├── gen/        # Generated Go stubs (buf generate)
│   ├── buf.gen.yaml
│   ├── Dockerfile
│   └── go.mod
├── http/           # HTTP implementation (JSON POST /check)
│   ├── main.go     # HTTP server (:8080) with /check and /token
│   ├── auth.go     # Auth check handler + JWT helpers
│   ├── auth_test.go
│   ├── Dockerfile
│   └── go.mod
└── README.md
```

## Protocol overview

### gRPC

EdgeQuota calls `edgequota.auth.v1.AuthService/Check` with a `CheckRequest` containing the HTTP method, path, headers, and remote address. The service returns a `CheckResponse` indicating allow/deny. When allowed, `request_headers` are injected into the upstream request.

Proto definitions: [buf.build/edgequota/edgequota](https://buf.build/edgequota/edgequota)

### HTTP

EdgeQuota sends a `POST` to the configured URL with a JSON body matching the `CheckRequest` schema. The service responds with a JSON `CheckResponse`.

**Request body** (JSON):
```json
{
  "method": "GET",
  "path": "/api/v1/resource",
  "headers": { "Authorization": "Bearer ...", "Content-Type": "application/json" },
  "remote_addr": "10.0.0.1:12345"
}
```

**Response body** (JSON, 200 = allow):
```json
{
  "allowed": true,
  "status_code": 200,
  "request_headers": { "X-Tenant-Id": "tenant-42" }
}
```

**Response body** (JSON, non-200 = deny):
```json
{
  "allowed": false,
  "status_code": 401,
  "deny_body": "missing Authorization header",
  "response_headers": { "Content-Type": "application/json" }
}
```

## Quick start

### gRPC variant

```bash
cd grpc
go run . -jwt-secret my-secret

# Create a token
curl -X POST http://localhost:8081/token \
  -H 'Content-Type: application/json' \
  -d '{"tenant_id": "tenant-1"}'

# Test with grpcurl
grpcurl -plaintext -d '{
  "method": "GET",
  "path": "/api/v1/test",
  "headers": {"Authorization": "Bearer <token>"}
}' localhost:50051 edgequota.auth.v1.AuthService/Check
```

### HTTP variant

```bash
cd http
go run . -jwt-secret my-secret

# Create a token
curl -X POST http://localhost:8080/token \
  -H 'Content-Type: application/json' \
  -d '{"tenant_id": "tenant-1"}'

# Test the check endpoint
curl -X POST http://localhost:8080/check \
  -H 'Content-Type: application/json' \
  -d '{
    "method": "GET",
    "path": "/api/v1/test",
    "headers": {"Authorization": "Bearer <token>"}
  }'
```

## EdgeQuota configuration

### gRPC auth

```yaml
auth:
  enabled: true
  timeout: "5s"
  failure_policy: "failclosed"
  grpc:
    address: "auth-service:50051"
```

### HTTP auth

```yaml
auth:
  enabled: true
  timeout: "5s"
  failure_policy: "failclosed"
  http:
    url: "http://auth-service:8080/check"
```

## Configuration

| Flag / Env var | Default | Description |
|---|---|---|
| `-jwt-secret` / `JWT_SECRET` | `edgequota-demo-secret` | HMAC secret for signing/validating JWTs |
| `-grpc-addr` / `GRPC_ADDR` | `:50051` | gRPC listen address (gRPC variant only) |
| `-http-addr` / `HTTP_ADDR` | `:8081` | HTTP listen address for token endpoint (gRPC variant) |
| `-addr` / `ADDR` | `:8080` | HTTP listen address (HTTP variant) |

## Docker

```bash
# gRPC
docker build -t edgequota-auth-grpc grpc/
docker run -p 50051:50051 -p 8081:8081 -e JWT_SECRET=my-secret edgequota-auth-grpc

# HTTP
docker build -t edgequota-auth-http http/
docker run -p 8080:8080 -e JWT_SECRET=my-secret edgequota-auth-http
```

## Tests

```bash
cd grpc && go test -v ./...
cd http && go test -v ./...
```

## Regenerating gRPC stubs

```bash
cd grpc && buf generate
```

Proto definitions are pulled from the [Buf Schema Registry](https://buf.build/edgequota/edgequota).

## Extending this template

To add your own auth logic:

1. **gRPC**: Modify `AuthService.Check()` in `grpc/auth.go`.
2. **HTTP**: Modify `AuthService.HandleCheck()` in `http/auth.go`.

Key extension points:
- Replace HMAC JWT validation with RS256/JWKS for production use.
- Query a database for tenant metadata and return it in `request_headers`.
- Add custom deny logic with specific `status_code` and `deny_body`.
- Return additional headers in `request_headers` (e.g. `X-Plan-Tier`, `X-Org-Id`).

## License

MIT
