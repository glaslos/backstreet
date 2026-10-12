# Backstreet

Backstreet is a single-host API for asynchronous Windows malware emulation with
[Mandiant Speakeasy](https://github.com/mandiant/speakeasy). A Go control plane exposes HTTP,
gRPC, and MCP while a network-isolated Python sidecar performs emulation.

> Speakeasy emulates samples instead of executing them natively, but parsers and emulators can
> still contain vulnerabilities. Run Backstreet on a dedicated analysis host. Do not treat the
> container boundary as equivalent to a hardened malware sandbox.

## Quick start

Requirements: Docker Engine with Compose.

```bash
export BACKSTREET_API_KEY='replace-with-a-long-random-value'
export BACKSTREET_API_KEY_HASHES="$(printf %s "$BACKSTREET_API_KEY" | sha256sum | cut -d' ' -f1)"
docker compose up --build
```

Fish:

```fish
set -x BACKSTREET_API_KEY 'replace-with-a-long-random-value'
set -x BACKSTREET_API_KEY_HASHES (printf %s $BACKSTREET_API_KEY | sha256sum | cut -d' ' -f1)
docker compose up --build
```

HTTP/MCP listen on `127.0.0.1:8080`; gRPC listens on `127.0.0.1:9090`.

Submit a PE file:

```bash
curl -fsS \
  -H "X-API-Key: $BACKSTREET_API_KEY" \
  -H "Idempotency-Key: example-1" \
  -F 'options={"timeoutSeconds":60,"strings":true}' \
  -F 'sample=@sample.exe' \
  http://127.0.0.1:8080/v1/analyses
```

Poll and retrieve a report:

```bash
curl -H "X-API-Key: $BACKSTREET_API_KEY" \
  http://127.0.0.1:8080/v1/analyses/ANALYSIS_ID
curl -H "X-API-Key: $BACKSTREET_API_KEY" \
  http://127.0.0.1:8080/v1/analyses/ANALYSIS_ID/report
```

## APIs

The canonical contract is [`api/proto/v1/analysis.proto`](api/proto/v1/analysis.proto).

### HTTP

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/analyses` | Multipart upload (`sample`, optional JSON `options`) |
| `GET` | `/v1/analyses` | List jobs with `page_size` and `page_token` |
| `GET` | `/v1/analyses/{id}` | Get job state |
| `POST` | `/v1/analyses/{id}/cancel` | Cancel a job |
| `GET` | `/v1/analyses/{id}/report` | Read the native Speakeasy report |
| `GET` | `/v1/analyses/{id}/artifacts` | List report and dropped-file artifacts |
| `GET` | `/v1/analyses/{id}/artifacts/{artifact}` | Download an artifact |

`/healthz` and Prometheus-format `/metrics` do not require an API key. All analysis endpoints do.

### gRPC

The `AnalysisService` is available on port 9090. Send the API key as `x-api-key` metadata.
`SubmitAnalysis` is a client stream: send one metadata message followed by sample chunks.

After installing `grpcurl`, health can be queried with:

```bash
grpcurl -plaintext -H "x-api-key: $BACKSTREET_API_KEY" \
  127.0.0.1:9090 backstreet.api.v1.AnalysisService/Health
```

Server reflection is intentionally disabled; use the checked-in protobuf contract.

### MCP

Streamable HTTP MCP is mounted at `http://127.0.0.1:8080/mcp`. Configure clients to send either
`X-API-Key` or `Authorization: Bearer ...`. Available tools:

- `submit_analysis` (base64 input, intended for bounded samples)
- `get_analysis`
- `cancel_analysis`
- `get_report`
- `list_artifacts`

Reports and artifacts are also MCP resources:

- `backstreet://analyses/{id}/report`
- `backstreet://analyses/{id}/artifacts/{artifact_id}`

Use HTTP or gRPC to upload/download large files.

## Analysis options

The public API deliberately exposes only bounded controls: PE versus shellcode, shellcode
architecture, timeout, instruction/API limits, all-entrypoint execution, strings, coverage,
memory tracing, memory snapshots, argv/environment, and modeled DNS responses. Arbitrary host
paths, Speakeasy volumes, GDB binding, and raw configuration overlays are rejected by design.

The complete native Speakeasy JSON report is preserved, including `report_version`. Clients
should tolerate fields added by future Speakeasy report versions.

## Configuration

| Variable | Default | Description |
|---|---:|---|
| `BACKSTREET_API_KEY_HASHES` | required | Comma-separated SHA-256 API-key hashes |
| `BACKSTREET_MAX_UPLOAD_BYTES` | 67108864 | Maximum sample size |
| `BACKSTREET_MAX_QUEUE_DEPTH` | 100 | Maximum queued jobs |
| `BACKSTREET_MAX_CONCURRENT` | 2 | Concurrent analyses |
| `BACKSTREET_REQUESTS_PER_MINUTE` | 120 | Per-key in-memory rate limit |
| `BACKSTREET_RETENTION_HOURS` | 168 | Terminal-job retention |
| `BACKSTREET_DATA_DIR` | `/data` | SQLite and content-addressed blob root |
| `BACKSTREET_HTTP_ADDR` | `:8080` | HTTP/MCP listen address |
| `BACKSTREET_GRPC_ADDR` | `:9090` | gRPC listen address |

SQLite uses WAL mode. On restart, interrupted `running` jobs return to `queued`. Hourly retention
removes expired terminal jobs and unreferenced blobs.

## Security model

- API keys are compared by their SHA-256 digests using constant-time comparison and are never
  logged.
- The worker runs as non-root with no network, a read-only root filesystem, dropped Linux
  capabilities, `no-new-privileges`, bounded PIDs/CPU/memory, and tmpfs scratch space.
- Samples and artifacts remain in the shared data volume and are addressed by SHA-256.
- Filenames, sizes, option cardinality, report sizes, and artifact sizes are bounded.
- The worker validates that every requested path remains below `/data`.

For stronger isolation, place the worker behind a VM or microVM boundary and store the data volume
on encrypted storage.

## Development

Generate protobuf code:

```bash
go run github.com/bufbuild/buf/cmd/buf@v1.59.0 generate
```

Run checks:

```bash
go test -race ./...
go vet ./...
uv sync --frozen --all-groups
uv run pytest
uv run ruff check worker
uv run mypy worker
```

Python dependencies are managed with [uv](https://docs.astral.sh/uv/) via
[`pyproject.toml`](pyproject.toml) and [`uv.lock`](uv.lock). Review Speakeasy
report/config changes before upgrading it.