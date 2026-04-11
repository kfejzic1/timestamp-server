# FROST Trusted Timestamping Server

A distributed trusted timestamping authority using the **FROST (Flexible Round-Optimized Schnorr Threshold)** protocol as specified in [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html). The system implements a *k*-of-*n* threshold signature scheme that eliminates any single point of failure — no single node ever possesses the full private key.

## Architecture

```
                    ┌─────────────────────┐
                    │   User / Browser    │
                    │   (SHA-256 hash)    │
                    └────────┬────────────┘
                             │ HTTP :8000
                    ┌────────▼────────────┐
                    │  Python Gateway     │
                    │  (FastAPI)          │
                    │  - REST API         │
                    │  - Session Manager  │
                    │  - Orchestrator     │
                    └──┬──────────┬───────┘
                       │          │
            ┌──────────▼──┐  ┌───▼──────────┐
            │ Go Signers  │  │ Go Aggregator│
            │ (×n nodes)  │  │              │
            │ - DKG       │  │ - Aggregate  │
            │ - Commit    │  │ - Verify     │
            │ - Sign      │  │              │
            └─────────────┘  └──────────────┘
```

**Components:**

| Service | Language | Role |
|---------|----------|------|
| **Gateway** | Python (FastAPI) | Stateless orchestrator, REST API, session state machine, frontend |
| **Signer** | Go | Holds secret key share, performs DKG rounds, commits nonces, produces partial signatures |
| **Aggregator** | Go | Combines partial signatures via `frost.AggregateSignatures()`, verifies final signature |

All cryptographic operations use the [`github.com/bytemare/frost`](https://github.com/bytemare/frost) and [`github.com/bytemare/dkg`](https://github.com/bytemare/dkg) libraries in Go to avoid cross-language math re-implementation risks.

**Ciphersuite:** `FROST(ristretto255, SHA-512)` — RFC 9591, Ciphersuite ID 1.

## Security Properties

- **No single point of failure:** The full private key is never reconstructed. At least *k* signers must cooperate.
- **E2E encrypted DKG:** Point-to-point secret shares during DKG are encrypted with X25519 + XSalsa20-Poly1305 (NaCl box). The Gateway cannot read them.
- **Timestamp validation:** Each signer independently validates the proposed timestamp against its own clock (±5s tolerance).
- **Encrypted key persistence:** Key shares are encrypted with AES-256-GCM before writing to disk.
- **mTLS ready:** Inter-service communication supports mutual TLS authentication.
- **Canonical message format:** A deterministic length-prefixed binary encoding ensures signers and the gateway agree on the exact bytes being signed.
- **Input validation:** The gateway enforces that `document_hash` is exactly 64 hex characters (a valid SHA-256 digest) before accepting any request.

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/) v2+
- Bash shell or PowerShell (for certificate generation)

## Quick Start

### 1. Generate mTLS Certificates

Inter-service communication uses mutual TLS. Generate the CA and service certificates before starting the cluster.

**Linux / macOS / Git Bash:**

```bash
bash certs/generate.sh
```

**Windows (PowerShell):**

```powershell
powershell -ExecutionPolicy Bypass -File certs\generate.ps1
```

> The PowerShell script automatically uses the OpenSSL bundled with Git for Windows
> (`C:\Program Files\Git\usr\bin\openssl.exe`) to avoid conflicts with other OpenSSL
> installations (e.g. PostgreSQL). If Git for Windows is not installed, install it from
> [git-scm.com](https://git-scm.com/).

If you skip this step the services fall back to plain HTTP between containers.

### 2. Start the Cluster

```bash
# Default: 5 signer nodes, threshold 3
docker compose up --build

# Custom signer count (also update MAX_SIGNERS in docker-compose.yml):
docker compose up --build --scale signer=7
```

### 3. Wait for Registration

The signers automatically register with the Gateway on startup. Watch the logs:

```
gateway-1     | INFO Signer registered: participant_id=1, url=http://...
gateway-1     | INFO Signer registered: participant_id=2, url=http://...
...
gateway-1     | INFO All 5 signers registered — ready for DKG
```

### 4. Initialize DKG

Trigger Distributed Key Generation via the web UI or API:

```bash
curl -X POST http://localhost:8000/api/dkg/start
```

This executes a 3-round Pedersen DKG with Verifiable Secret Sharing:

1. **Round 1:** Each signer generates a polynomial and broadcasts commitments with zero-knowledge proofs.
2. **Round 2:** Each signer computes secret shares for every other signer, encrypts them E2E, and sends via the Gateway.
3. **Round 3:** Each signer verifies received shares against commitments, derives its final key share, and persists it encrypted to disk.

On completion, the Gateway configures the Aggregator with the group's verification key and all public key shares.

**Abort/Retry:** If any signer fails VSS verification, the Gateway returns an error. All signers clear their DKG state, and the entire DKG can be restarted from scratch by calling the endpoint again. DKG is all-or-nothing.

### 5. Create a Timestamp

**Via Web UI:** Open [http://localhost:8000](http://localhost:8000), upload a document, and click "Sign Timestamp."

**Via API:**

```bash
# Hash a document
HASH=$(sha256sum document.pdf | cut -d' ' -f1)

# Request timestamp
curl -X POST http://localhost:8000/api/timestamp \
  -H "Content-Type: application/json" \
  -d "{\"document_hash\": \"$HASH\"}"
```

This performs a two-round FROST signing session:

1. **Commit Round:** The Gateway selects *k* random signers and collects nonce commitments.
2. **Sign Round:** The Gateway builds a canonical message, sends it with the sorted commitment list. Each signer validates the timestamp and produces a partial signature.
3. **Aggregation:** The Aggregator combines the shares and verifies the final Schnorr signature.

**Response:** A JSON timestamp token:

```json
{
  "version": 1,
  "hash_algorithm": "SHA-256",
  "document_hash": "e3b0c44298fc1c149afbf4c8996fb924...",
  "timestamp": "2026-03-10T14:30:00.123Z",
  "serial_number": "550e8400-e29b-41d4-a716-446655440000",
  "ciphersuite": "FROST-RISTRETTO255-SHA512",
  "verification_key": "74144431f64b052a...",
  "signature": "a1b2c3d4...",
  "participants": [1, 3, 5],
  "threshold": 3,
  "max_signers": 5
}
```

### 6. Verify a Timestamp

**Via Web UI:** Go to the Verify tab, upload the original document and the token JSON.

**Via API:**

```bash
curl -X POST http://localhost:8000/api/verify \
  -H "Content-Type: application/json" \
  -d '{"document_hash": "e3b0c44...", "token": { ... }}'
```

Verification re-computes the canonical message from the token fields and checks the signature against the aggregate public key. No private key material is needed.

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web UI |
| `/api/register` | POST | Signer self-registration (internal) |
| `/api/dkg/start` | POST | Trigger DKG ceremony |
| `/api/timestamp` | POST | Create a timestamp token |
| `/api/verify` | POST | Verify a timestamp token |
| `/api/status` | GET | Cluster health and DKG status |

Interactive API documentation is available at [http://localhost:8000/docs](http://localhost:8000/docs) while the cluster is running.

## Testing

The project includes an end-to-end test suite that exercises the full protocol against a live Docker Compose cluster.

### Test Structure

```
tests/
├── requirements.txt          # pytest, pytest-timeout, httpx
└── e2e/
    ├── conftest.py           # Session fixtures: gateway client, cluster readiness
    ├── test_timestamp_flow.py   # Happy-path and token integrity tests
    └── test_input_validation.py # Malformed input and error-code tests
```

### Running the Tests Locally

**Step 1 — Generate certificates and start the cluster** (if not already running):

```bash
# Linux / macOS / Git Bash
bash certs/generate.sh && docker compose up --build -d

# Windows PowerShell
powershell -ExecutionPolicy Bypass -File certs\generate.ps1
docker compose up --build -d
```

**Step 2 — Create a Python virtual environment and install test dependencies:**

```bash
python -m venv .venv

# Linux / macOS / Git Bash
source .venv/bin/activate

# Windows PowerShell
.\.venv\Scripts\Activate.ps1

pip install -r tests/requirements.txt
```

**Step 3 — Run the full test suite:**

```bash
pytest tests/e2e/ -v
```

The fixtures handle all waiting automatically: they poll until all signers have registered, trigger DKG, and wait for it to complete before any signing tests execute. Total wall-clock time is typically under 3 minutes on the first run (dominated by `docker compose --build`).

**Run a single file:**

```bash
pytest tests/e2e/test_input_validation.py -v
pytest tests/e2e/test_timestamp_flow.py -v
```

**Step 4 — Tear down when done:**

```bash
docker compose down --volumes
```

### Rebuilding After Code Changes

If you modify gateway source code, rebuild its container before re-running tests:

```bash
docker compose up --build -d gateway
pytest tests/e2e/ -v
```

> Rebuilding the gateway resets in-memory state (signers, DKG). The `cluster_ready`
> fixture detects this and re-runs DKG automatically.

### CI

Tests run automatically on every push and pull request to `main`/`master` via GitHub Actions (`.github/workflows/e2e.yml`). The workflow:

1. Generates TLS certificates with `bash certs/generate.sh`
2. Builds and starts all containers with `docker compose up --build -d`
3. Installs test dependencies and runs `pytest tests/e2e/ -v`
4. Prints container logs on failure for debugging
5. Always tears down with `docker compose down --volumes`

### What Is Tested

| Category | Tests |
|----------|-------|
| **Cluster readiness** | Gateway reachable, all signers register, DKG completes, status fields correct |
| **DKG idempotency** | Calling `/api/dkg/start` again returns `already_complete` |
| **Token creation** | All required fields present, correct types and values |
| **Token integrity** | Timestamp is valid ISO-8601, serial is a UUID, participant IDs in range, threshold matches cluster |
| **Verification key stability** | All tokens share the same group key matching `/api/status` |
| **Verification** | Valid tokens pass, tampered hash/signature/timestamp field all fail |
| **Independence** | Multiple tokens have unique serials; same document twice gives two distinct valid tokens |
| **Concurrency** | 5 parallel timestamp requests all succeed with unique serials |
| **Input validation** | Non-hex, wrong-length, empty, null, and wrong-type hashes all return 4xx/5xx |
| **Token field validation** | Missing required token fields return 422; wrong field types return 422 |
| **Frontend** | `/` and `/static/index.html` serve HTML |
| **OpenAPI** | Schema lists all endpoints; `/docs` UI is reachable |

## Canonical Message Format

The signed message uses a deterministic length-prefixed binary encoding (big-endian) to ensure byte-identical output in Go and Python:

```
[2 bytes: ciphersuite ID (uint16)]
[1 byte:  hash algorithm name length]
[N bytes: hash algorithm name, e.g. "SHA-256"]
[4 bytes: document hash length (uint32)]
[M bytes: document hash (raw bytes)]
[4 bytes: timestamp length (uint32)]
[T bytes: RFC 3339 timestamp string]
[4 bytes: serial number length (uint32)]
[S bytes: UUID string]
```

### Test Vector

For cross-language validation:

```
Ciphersuite ID: 1 (0x0001)
Hash Algorithm: "SHA-256"
Document Hash:  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 (SHA-256 of empty string)
Timestamp:      "2026-01-01T00:00:00.000Z"
Serial:         "00000000-0000-0000-0000-000000000000"

Expected canonical message (hex):
0001 07 5348412d323536
00000020 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
00000018 323032362d30312d30315430303a30303a30302e3030305a
00000024 30303030303030302d303030302d303030302d303030302d303030303030303030303030
```

## Project Structure

```
timestamp-server/
├── docker-compose.yml          # Orchestrates all services
├── .gitattributes              # Enforces LF line endings for shell scripts
├── README.md
├── certs/
│   ├── generate.sh             # mTLS certificate generation (Linux/macOS)
│   └── generate.ps1            # mTLS certificate generation (Windows PowerShell)
├── tests/
│   ├── requirements.txt        # Test dependencies (pytest, httpx)
│   └── e2e/
│       ├── conftest.py         # Shared fixtures (gateway client, cluster readiness)
│       ├── test_timestamp_flow.py   # Happy-path and integrity tests
│       └── test_input_validation.py # Input validation and error-code tests
├── .github/
│   └── workflows/
│       └── e2e.yml             # GitHub Actions CI workflow
├── signer/                     # Go signer microservice
│   ├── Dockerfile
│   ├── go.mod
│   ├── main.go                 # HTTP server, registration, health
│   ├── dkg.go                  # DKG round handlers (Start/Continue/Finalize)
│   ├── sign.go                 # FROST commit + sign handlers
│   ├── storage.go              # AES-256-GCM encrypted key share persistence
│   ├── message.go              # Canonical message encoding + timestamp validation
│   └── e2e.go                  # X25519 NaCl box for E2E DKG share encryption
├── aggregator/                 # Go aggregator service
│   ├── Dockerfile
│   ├── go.mod
│   ├── main.go                 # HTTP server, FROST configuration
│   ├── aggregate.go            # Signature aggregation with verification
│   └── verify.go               # Standalone signature verification
└── gateway/                    # Python FastAPI gateway
    ├── Dockerfile
    ├── requirements.txt
    ├── main.py                 # FastAPI app, routes, input validation
    ├── models.py               # Pydantic models, token schema, canonical encoding
    ├── session.py              # UUID-keyed signing session state machine
    ├── orchestrator.py         # DKG + signing round coordination
    └── static/
        └── index.html          # Web UI
```

## Configuration

Environment variables (set in `docker-compose.yml`):

| Variable | Service | Description |
|----------|---------|-------------|
| `THRESHOLD` | Gateway, Signer | Minimum signers required (*k*) |
| `MAX_SIGNERS` | Gateway, Signer | Total number of signer nodes (*n*) |
| `AGGREGATOR_URL` | Gateway | URL of the aggregator service |
| `GATEWAY_URL` | Signer | URL of the gateway for registration |
| `SIGNER_PORT` | Signer | HTTP port for the signer (default: 8081) |
| `ENCRYPTION_KEY` | Signer | 32-byte hex key for AES-256-GCM key share encryption |

## Protocol Lifecycle

```
Registration ──► DKG (3 rounds) ──► Ready ──► Signing Sessions (2 rounds each)
                     │                              │
                     ▼                              ▼
              Key shares persisted          Timestamp tokens issued
              to encrypted volumes          with threshold signatures
```

1. **Registration:** Signers start and register with the Gateway, receiving sequential participant IDs and exchanging X25519 ephemeral public keys for DKG E2E encryption.

2. **DKG:** Three-round Pedersen DKG produces secret key shares (never leave the signer) and a shared verification key. Shares are encrypted E2E between signers — the Gateway acts purely as a message relay.

3. **Signing:** Two-round FROST protocol. The Gateway selects *k* signers, collects nonce commitments (Round 1), builds the canonical message, and collects partial signatures (Round 2). Each signer validates the timestamp independently.

4. **Aggregation:** The Go Aggregator combines partial signatures into a standard Schnorr signature and verifies it before returning to the Gateway.

5. **Verification:** Anyone can verify the signature using the aggregate public key. No private information needed.

## Production Considerations

This implementation is designed for educational and demonstration purposes. For production use:

- **KMS/HSM integration:** The `ENCRYPTION_KEY` should come from a key management service, not an environment variable.
- **Per-signer volumes:** Each signer should have its own encrypted volume rather than sharing one.
- **Per-signer encryption keys:** In production, each signer should have a unique encryption key.
- **NTP authentication:** Use NTS (Network Time Security) instead of plain NTP for clock synchronization.
- **Audit logging:** Implement an append-only log of all issued timestamps for non-repudiation.
- **Key resharing:** Implement proactive secret sharing to rotate key shares without changing the public key.
- **Rate limiting:** Add rate limiting to the timestamping endpoint.
- **Persistent sessions:** Use Redis or similar for signing session state instead of in-memory storage.

## License

This project is developed for academic purposes as part of Security Technologies coursework.
