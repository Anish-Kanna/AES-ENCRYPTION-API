<p align="center">
  <img src="https://img.shields.io/badge/Java-21-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white" alt="Java 21"/>
  <img src="https://img.shields.io/badge/AES--256--GCM-Encryption-2ea44f?style=for-the-badge&logo=letsencrypt&logoColor=white" alt="AES-256-GCM"/>
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker"/>
</p>

# 🔐 AES-ENC-DEPLOY

A lightweight, zero-dependency\* REST API server for **AES-256-GCM** file encryption and decryption — built entirely with the Java standard library.

> \*The only external dependency is [Gson](https://github.com/google/gson) for JSON parsing.

---

## ✨ Features

| Feature | Details |
|---|---|
| **AES-256-GCM** | Authenticated encryption with 128-bit authentication tags |
| **PBKDF2 Key Derivation** | `PBKDF2WithHmacSHA256` · 12,000 iterations · 16-byte random salt |
| **Streaming I/O** | Chunked encrypt/decrypt — handles files up to **10 MB** per request |
| **Content Negotiation** | Responds with raw binary or Base64-encoded JSON based on `Accept` header |
| **API Key Auth** | All encrypt/decrypt endpoints gated behind `X-API-Key` header |
| **IP Rate Limiting** | 20 requests per IP per 60-second sliding window |
| **Structured Logging** | JSON-formatted request logs with method, path, status, and latency |
| **Graceful Shutdown** | JVM shutdown hook for clean server and thread pool teardown |
| **Docker Support** | Production-ready Dockerfile included |

---

## 📁 Project Structure

```
AES-ENC-DEPLOY/
├── src/
│   ├── core/
│   │   └── AES_service.java      # Core AES-256-GCM encrypt/decrypt engine
│   └── service/
│       └── MainServer.java       # HTTP server, handlers, middleware chain
├── Dockerfile                    # Container build configuration
├── gson-2.13.2.jar               # Gson library (bundled)
└── .gitignore
```

---

## 🛠️ Getting Started

### Prerequisites

- **Java 21+** (or any JDK that supports `eclipse-temurin:21`)
- **Docker** (optional, for containerized deployment)

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `API_KEY` | ✅ | Secret key for authenticating API requests |
| `PORT` | ❌ | Server port (defaults to `8080`) |

---

### Run Locally

```bash
# Set the API key
export API_KEY="your-secret-api-key"

# Compile
javac -cp gson-2.13.2.jar -d out src/core/AES_service.java src/service/MainServer.java

# Run
java -cp out:gson-2.13.2.jar service.MainServer
```

> **Windows:** Replace `:` with `;` in the classpath — e.g., `out;gson-2.13.2.jar`

### Run with Docker

```bash
# Build the image
docker build -t aes-enc-deploy .

# Run the container
docker run -d \
  -p 8080:8080 \
  -e API_KEY="your-secret-api-key" \
  --name aes-server \
  aes-enc-deploy
```

---

## 📡 API Reference

**Base URL:** `http://localhost:8080`

All encrypt/decrypt endpoints require the `X-API-Key` header.

---

### `GET /api/v1/health`

Health check endpoint (no authentication required).

**Response:**
```json
{ "status": "UP" }
```

---

### `POST /api/v1/encrypt`

Encrypt raw file data using a password.

**Headers:**

| Header | Required | Description |
|---|---|---|
| `X-API-Key` | ✅ | API authentication key |
| `X-Password` | ✅ | Encryption password |
| `X-Extension` | ✅ | Original file extension (e.g., `pdf`, `png`, `txt`) |
| `Accept` | ❌ | `application/json` for Base64 response; omit for raw binary |

**Request Body:** Raw file bytes (`application/octet-stream`)

#### Example — JSON Response

```bash
curl -X POST http://localhost:8080/api/v1/encrypt \
  -H "X-API-Key: your-secret-api-key" \
  -H "X-Password: my-strong-password" \
  -H "X-Extension: txt" \
  -H "Accept: application/json" \
  --data-binary @myfile.txt
```

```json
{
  "status": "success",
  "data": "AACrdQEB..."
}
```

#### Example — Raw Binary Response

```bash
curl -X POST http://localhost:8080/api/v1/encrypt \
  -H "X-API-Key: your-secret-api-key" \
  -H "X-Password: my-strong-password" \
  -H "X-Extension: pdf" \
  --data-binary @document.pdf \
  -o document.enc
```

---

### `POST /api/v1/decrypt`

Decrypt previously encrypted data using the same password.

**Headers:**

| Header | Required | Description |
|---|---|---|
| `X-API-Key` | ✅ | API authentication key |
| `X-Password` | ✅ | Decryption password (must match the encryption password) |
| `Content-Type` | ❌ | `application/json` if sending Base64 JSON; omit for raw binary |
| `Accept` | ❌ | `application/json` for Base64 response; omit for raw binary |

#### Example — JSON Input & Output

```bash
curl -X POST http://localhost:8080/api/v1/decrypt \
  -H "X-API-Key: your-secret-api-key" \
  -H "X-Password: my-strong-password" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"data": "AACrdQEB..."}'
```

```json
{
  "status": "success",
  "extension": "txt",
  "data": "SGVsbG8gV29ybGQ="
}
```

#### Example — Raw Binary

```bash
curl -X POST http://localhost:8080/api/v1/decrypt \
  -H "X-API-Key: your-secret-api-key" \
  -H "X-Password: my-strong-password" \
  --data-binary @document.enc \
  -o document.pdf
```

---

## ⚠️ Error Responses

The server returns errors in plain text or JSON depending on the `Accept` header.

| Status Code | Meaning |
|---|---|
| `400` | Bad request — missing headers, empty body, or invalid JSON/Base64 |
| `401` | Authentication failed — wrong password or tampered data |
| `403` | Forbidden — invalid or missing `X-API-Key` |
| `405` | Method not allowed |
| `413` | Payload too large (> 10 MB) |
| `429` | Rate limit exceeded (> 20 req/min per IP) |
| `500` | Internal server error |

**JSON error format:**
```json
{
  "status": "error",
  "message": "Missing X-Password or X-Extension"
}
```

---

## 🔒 Binary Container Format

Encrypted output follows a custom binary container format:

```
┌──────────────┬─────────┬───────────┬──────────┬──────────┬─────────┬───────────┬────────────────────┐
│ Magic Bytes  │ Version │ Algorithm │    IV    │   Salt   │ Ext Len │ Extension │   Ciphertext + Tag │
│   4 bytes    │ 1 byte  │  1 byte   │ 12 bytes │ 16 bytes │ 1 byte  │  N bytes  │     Variable       │
└──────────────┴─────────┴───────────┴──────────┴──────────┴─────────┴───────────┴────────────────────┘
```

| Field | Size | Description |
|---|---|---|
| Magic | 4 B | `0x0000AB64` — file signature |
| Version | 1 B | Format version (`0x01`) |
| Algorithm | 1 B | Algorithm ID (`0x01` = AES-256-GCM) |
| IV | 12 B | Random initialization vector |
| Salt | 16 B | Random salt for PBKDF2 key derivation |
| Ext Length | 1 B | Length of the original file extension |
| Extension | N B | Original file extension (UTF-8) |
| Ciphertext | Var | AES-GCM encrypted data + 128-bit auth tag |

---

## 🧩 Middleware Chain

Requests to `/encrypt` and `/decrypt` pass through a layered handler chain:

```
Request → LoggingHandler → RateLimitHandler → APIHandler → encrypt/decryptHandler
```

1. **LoggingHandler** — Structured JSON logging with timestamps, IP, status, and latency
2. **RateLimitHandler** — Per-IP sliding window rate limiter (20 req / 60s)
3. **APIHandler** — Validates `X-API-Key` header against the server's `API_KEY` env var
4. **encryptHandler / decryptHandler** — Core business logic

---

## 📄 License

This project is open source. Feel free to use, modify, and distribute.
