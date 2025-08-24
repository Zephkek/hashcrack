<div align="center">

# 🔓 HashCrack

**A powerful, fast, and user-friendly hash cracking toolkit**

[![Go](https://img.shields.io/badge/Go-1.23%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

<img src="docs/logo.png" alt="HashCrack Logo" width="300" />

**HashCrack** is a Go-based, high-performance hash cracking toolkit featuring both a modern Web UI and CLI interface. Built with Docker-first architecture for seamless deployment and maximum portability.

[Features](#-features) • [Quick Start](#-quick-start) • [Attack Modes](#-attack-modes) • [Web UI](#-web-ui) • [CLI Usage](#-cli-usage)

</div>

---

## 🚀 Features

- **⚡ High Performance**: Multi-threaded cracking with optimized worker pools
- **🎯 Six Attack Modes**: Dictionary, Mask, Brute Force, Combination, Hybrid, and Association
- **📊 Real-time Monitoring**: Live progress tracking with speed, ETA, and completion stats
- **💾 State Persistence**: Automatic progress saving and resumption of interrupted tasks
- **🧠 Smart Detection**: Automatic algorithm identification with heuristics
- **📁 Flexible Wordlists**: Upload custom wordlists or use built-in samples
- **🌐 Dual Interface**: Modern Web UI and powerful CLI for all use cases
- **🐳 Docker Ready**: One command deployment with Docker Compose
- **⏯️ Task Management**: Pause, resume, stop, and delete tasks with full state persistence

## 🛠️ Supported Algorithms

<details>
<summary>Full supported algorithms</summary>

Supported algorithms:

- 3des
- adobe-aem-sha256
- adobe-aem-sha512
- aes-128-ecb
- aes-192-ecb
- aes-256-ecb
- apache-apr1-md5
- argon2id
- arubaos
- authme-sha256
- bcrypt
- bcrypt-hmac-sha256-pass
- bcrypt-md5-pass
- bcrypt-sha1-pass
- bcrypt-sha256-pass
- bcrypt-sha512-pass
- blake2b-256
- blake2b-512
- blake2s-256
- chacha20
- cisco
- cisco-asa-md5
- cisco-ios-pbkdf2-sha256
- cisco-ios-scrypt
- cisco-ios-type4-sha256
- cisco-ise-sha256
- cisco-pix-md5
- cisco7
- citrix-netscaler-pbkdf2
- citrix-netscaler-sha1
- citrix-netscaler-sha512
- coldfusion-10
- crc32
- crc32c
- crc64jones
- dahua-md5
- des
- descrypt
- dnssec-nsec3
- domain-cached-credentials
- domain-cached-credentials2
- episerver-6x-net4
- episerver-6x-net4-plus
- filezilla-server
- fortigate
- fortigate256
- gost-94
- gost-streebog-256
- gost-streebog-512
- half-md5
- hmac-ripemd160-pass
- hmac-ripemd160-salt
- hmac-ripemd320-pass
- hmac-ripemd320-salt
- hmac-streebog-256-pass
- hmac-streebog-256-salt
- hmac-streebog-512-pass
- hmac-streebog-512-salt
- hmailserver
- huawei-sha1-md5-salt
- java-hashcode
- juniper-ive
- juniper-netscreen
- juniper-sha1crypt
- keccac-224
- keccac-256
- keccac-384
- keccac-512
- ldap_md5
- ldap_sha1
- lm
- lotus-notes-5
- lotus-notes-6
- lotus-notes-8
- macos-10.4-10.6
- macos-10.7
- macos-10.8-pbkdf2
- md4
- md5
- md5-md5-md5-pass
- md5-md5-md5-pass-salt
- md5-md5-md5-pass-salt1-salt2
- md5-md5-pass-md5-salt
- md5-salt-md5-pass-salt
- md5-sha1-md5-pass
- md5-sha1-pass-md5-pass-sha1-pass
- md5-sha1-pass-salt
- md5-sha1-salt-md5-pass
- md5-sha1-salt-pass
- md5-strtoupper-md5-pass
- md5-utf16le
- md5-utf16le-pass-salt
- md5crypt
- md6-256
- mongodb-scram-sha1
- mongodb-scram-sha256
- mssql-2000
- mssql-2005
- mssql-2012
- murmurhash
- murmurhash3
- murmurhash64a
- murmurhash64a-zero
- mysql
- mysql-a-sha256crypt
- mysql-cram-sha1
- mysql323
- mysql41
- netiq-sspr-md5
- netiq-sspr-pbkdf2-sha1
- netiq-sspr-pbkdf2-sha256
- netiq-sspr-pbkdf2-sha512
- netiq-sspr-sha1
- netiq-sspr-sha1-salt
- netiq-sspr-sha256-salt
- netiq-sspr-sha512-salt
- nsldap-sha1
- nsldaps-ssha1
- ntlm
- openedge-progress
- oracle-h
- oracle-s
- oracle-t
- oracle-tm-sha256
- pbkdf1-sha1
- pbkdf2-hmac-md5
- pbkdf2-hmac-sha1
- pbkdf2-hmac-sha256
- pbkdf2-hmac-sha512
- pbkdf2-sha1
- pbkdf2-sha256
- pbkdf2-sha512
- peoplesoft
- peoplesoft-ps-token
- postgresql
- postgresql-cram-md5
- postgresql-scram-sha256
- radmin3
- redhat-389-ds-pbkdf2
- ripemd160
- rsa-netwitness-sha256
- sap-codvn-b
- sap-codvn-f
- sap-codvn-h-issha1
- sap-codvn-h-issha512
- scrypt
- sha1
- sha1-cx
- sha1-md5-md5-pass
- sha1-md5-pass
- sha1-md5-pass-salt
- sha1-salt-pass-salt
- sha1-salt-sha1-pass
- sha1-salt-sha1-pass-salt
- sha1-salt-sha1-utf16le-username-utf16le-pass
- sha1-salt-utf16le-pass
- sha1-salt1-pass-salt2
- sha1-sha1-pass
- sha1-sha1-pass-salt
- sha1-sha1-salt-pass-salt
- sha1-utf16le
- sha1-utf16le-pass-salt
- sha2-224
- sha2-256
- sha2-384
- sha2-512
- sha224-pass-salt
- sha224-salt-pass
- sha224-sha1-pass
- sha224-sha224-pass
- sha256
- sha256-salt-pass-salt
- sha256-salt-sha256-bin-pass
- sha256-salt-sha256-pass
- sha256-salt-utf16le-pass
- sha256-sha256-bin-pass
- sha256-sha256-pass-salt
- sha256-utf16le
- sha256-utf16le-pass-salt
- sha256crypt
- sha3-224
- sha3-256
- sha3-384
- sha3-512
- sha384
- sha384-salt-pass
- sha384-salt-utf16le-pass
- sha384-utf16le
- sha384-utf16le-pass-salt
- sha512
- sha512-salt-utf16le-pass
- sha512-sha512-bin-pass-salt
- sha512-sha512-pass-salt
- sha512-utf16le
- sha512-utf16le-pass-salt
- sha512crypt
- shake128
- shake256
- sm3
- sm3crypt
- solarwinds-orion
- solarwinds-orion-v2
- solarwinds-serv-u
- ssha-256-base64
- ssha-512-base64
- sybase-ase
- whirlpool

</details>

**200+ algorithms supported** including all major hash types, database authentication schemes, key derivation functions, and application-specific formats.

<details>
<summary>📋 View all supported algorithms</summary>

- 3des, adobe-aem-sha256, adobe-aem-sha512, aes-128-ecb, aes-192-ecb, aes-256-ecb
- apache-apr1-md5, argon2id, arubaos, authme-sha256, bcrypt, bcrypt-hmac-sha256-pass
- bcrypt-md5-pass, bcrypt-sha1-pass, bcrypt-sha256-pass, bcrypt-sha512-pass
- blake2b-256, blake2b-512, blake2s-256, chacha20, cisco, cisco-asa-md5
- cisco-ios-pbkdf2-sha256, cisco-ios-scrypt, cisco-ios-type4-sha256, cisco-ise-sha256
- cisco-pix-md5, cisco7, citrix-netscaler-pbkdf2, citrix-netscaler-sha1
- citrix-netscaler-sha512, coldfusion-10, crc32, crc32c, crc64jones, dahua-md5
- des, descrypt, dnssec-nsec3, domain-cached-credentials, domain-cached-credentials2
- episerver-6x-net4, episerver-6x-net4-plus, filezilla-server, fortigate, fortigate256
- md5, sha1, sha256, sha512, ntlm, mysql, oracle, postgresql, mssql, and many more...

*Run `hashcrack list` for the complete list*

</details>

---

## 🎯 Attack Modes

### 🔤 Dictionary Attack
**Most effective for common passwords**
- Uses wordlists containing common passwords
- Supports custom wordlists (`.txt`/`.lst` files)
- Built-in `rockyou-mini.txt` sample included
- Rule-based transformations: `+c` (capitalize), `+d2` (append digits)

### 🎭 Mask Attack  
**Perfect when you know password patterns**
- Pattern-based with placeholders: `?l?l?l?d?d` (3 letters + 2 digits)
- `?l` lowercase, `?u` uppercase, `?d` digit, `?s` symbol
- Highly efficient for structured passwords

### 🔄 Brute Force
**Exhaustive search through all combinations**
- Tries all possible character combinations
- Best for short passwords (1-6 characters)
- ⚠️ Exponentially slow for longer passwords

### 🔗 Combination Attack
**Merges two wordlists**
- Concatenates entries from two wordlists
- Optional separator support
- Great for firstname+lastname patterns

### ⚡ Hybrid Attack
**Wordlist + Pattern combination**
- Two modes: Wordlist+Mask or Mask+Wordlist
- Combines dictionary words with patterns
- Example: "password" + "123"

### 🧠 Association Attack
**Context-aware password generation**
- Uses personal information (username, email, company)
- Generates common variations and transformations
- Effective against personalized passwords

---

## 💾 State Persistence

**Automatic state saving and resumption for long-running tasks**

- ✅ **Automatic checkpoints**: Progress saved every few seconds
- ✅ **Resume capability**: Continue exactly where you left off
- ✅ **Cross-session recovery**: Survives container restarts and system reboots
- ✅ **Task management**: Pause, resume, stop, and delete via Web UI
- ✅ **JSON state files**: Human-readable format in `states/` directory

### What Gets Saved
- Progress tracking (attempts tried, current position)
- Task configuration (algorithm, target, parameters)  
- Timing information (runtime, pause/resume timestamps)
- Resume data (exact position to continue from)

---

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Git (to clone the repository)

### 1. Clone and Start
```bash
git clone <repository-url>
cd hashcrack-main
docker compose up --build -d
```

### 2. Access the Web UI
Open your browser and navigate to:
```
http://localhost:8080
```

### 3. Start Cracking!
1. 📝 Enter your hash
2. 🎯 Choose an attack mode  
3. ⚙️ Configure parameters
4. ▶️ Click "Start Attack"
5. 📊 Watch real-time progress

That's it! 🎉

---

## 🖥️ CLI Usage

- Volume: the current repo is mounted at `/data` in the container.
- Uploads: saved under `uploads/` in your repo.
- Default port: `8080` (mapped to host `8080`).

To stop and clean up:
```powershell
docker compose down
```

---

## Using the CLI (inside the container)
Run the CLI with `docker compose exec` so paths like `uploads/...` match the mounted `/data`.

### Basic Commands

**List supported algorithms:**
```powershell
docker compose exec hashcrack hashcrack list
```

### Attack Examples

**Dictionary Attack:**
```powershell
# Basic wordlist attack (MD5 of "hello")
$hash = "5d41402abc4b2a76b9719d911017c592"
docker compose exec hashcrack hashcrack crack -a md5 -h $hash -w uploads/wordlist.txt

# With transformation rules
docker compose exec hashcrack hashcrack crack -a md5 -h $hash -w uploads/wordlist.txt --rules "+c,+d2"
```

**Mask Attack:**
```powershell
# 4 letters + 2 digits pattern
docker compose exec hashcrack hashcrack crack -a sha1 -h $hash -m "?l?l?l?l?d?d"
```

**Combination Attack:**
```powershell
# Combine two wordlists
docker compose exec hashcrack hashcrack combination -a md5 -h $hash \
  --wordlist1 uploads/first-names.txt --wordlist2 uploads/last-names.txt
```

**Hybrid Attack:**
```powershell
# Wordlist + mask (append 2 digits to dictionary words)
docker compose exec hashcrack hashcrack hybrid -a sha256 -h $hash \
  -w uploads/wordlist.txt -m "?d?d"
```

**Association Attack:**
```powershell
# Generate candidates from user context
docker compose exec hashcrack hashcrack association -a md5 -h $hash \
  --username "john.doe" --email "john@company.com"
```

### Advanced Options
- `--workers 8` - Set number of concurrent workers
- `--timeout 30m` - Set maximum runtime  
- `--log crack.log` - Save detailed logs
- `--verbose` - Show detailed progress

**Algorithm-specific parameters:**
- `--bcrypt-cost 12` - For bcrypt hashes
- `--scrypt-n 32768 --scrypt-r 8 --scrypt-p 1` - For scrypt
- `--argon-time 1 --argon-memory 65536` - For Argon2
- `--pbkdf2-iterations 10000` - For PBKDF2

---

## Web UI
1. **Start**: `docker compose up --build -d`
2. **Open**: http://localhost:8080
3. **Interactive Interface**:
   - **Step 1**: Enter target hash → automatic algorithm detection with suggestions
   - **Step 2**: Choose attack method from 6 available modes:
     - **Dictionary Attack**: Upload wordlist or use built-in sample
     - **Mask Attack**: Define patterns with `?l?u?d?s` placeholders  
     - **Brute Force**: Set character range and length limits
     - **Combination**: Combine two wordlists with optional separator
     - **Hybrid**: Mix wordlist entries with mask patterns
     - **Association**: Generate candidates from context (username, email, etc.)
   - **Step 3**: Configure attack parameters, workers, rules
   - **Step 4**: Monitor real-time progress with speed, ETA, and completion stats

4. **Task Management**:
   - **Pause/Resume**: Safely pause tasks and resume later
   - **Task History**: View all previous, current, and queued tasks
   - **Progress Tracking**: Real-time updates via Server-Sent Events
   - **State Persistence**: Automatic progress saving and recovery

5. **File Management**:
   - Upload custom wordlists (`.txt`/`.lst` files)
   - Built-in `rockyou-mini.txt` sample included
   - Automatic file validation and format checking

**Real-time Updates**: If SSE disconnects, the UI automatically falls back to polling and continues displaying progress and results.

---

## Project layout
```
cmd/hashcrack/        # CLI entrypoint
internal/web/         # HTTP server, REST + SSE, task manager
internal/hashes/      # Hash/KDF registry + implementations
pkg/mask/             # Concurrent mask generator/runner
pkg/bruteforce/       # Concurrent brute forcer
web/static, template  # UI assets
uploads/              # Uploaded wordlists (mounted)
```

---

## API reference

### Core Endpoints
| Method | Path | Description |
|---|---|---|
| GET | `/api/stats` | Runtime and aggregate task stats |
| GET | `/api/algorithms` | Supported algorithms list |
| GET | `/api/detect?target=...` | Algorithm suggestions for a target hash |
| GET | `/api/events` | SSE stream with real-time task events |

### Task Management
| Method | Path | Description |
|---|---|---|
| GET | `/api/tasks` | List all tasks (active, paused, completed) |
| POST | `/api/tasks` | Create a new cracking task |
| GET | `/api/tasks/{id}` | Get specific task details and progress |
| POST | `/api/tasks/{id}/stop` | Stop a running task |
| POST | `/api/tasks/{id}/pause` | Pause a running task (saves state) |
| POST | `/api/tasks/{id}/resume` | Resume a paused task |
| DELETE | `/api/tasks/{id}` | Delete a task and its state |

### File & State Management  
| Method | Path | Description |
|---|---|---|
| POST | `/api/uploads` | Upload wordlist (`multipart/form-data`, field `file`) |
| GET | `/api/resumable` | List tasks that can be resumed |

<details>
<summary>Create Task Examples (JSON body)</summary>

**Dictionary Attack:**
```json
{
  "algo": "md5",
  "target": "5d41402abc4b2a76b9719d911017c592",
  "mode": "wordlist",
  "use_default_wordlist": true,
  "rules": ["+c", "+d2"],
  "workers": 4
}
```

**Mask Attack:**
```json
{
  "algo": "sha256",
  "target": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
  "mode": "mask",
  "mask": "?l?l?l?l?d?d",
  "workers": 8
}
```

**Combination Attack:**
```json
{
  "algo": "sha1",
  "target": "356a192b7913b04c54574d18c28d46e6395428ab",
  "mode": "combination",
  "wordlist1": "uploads/first-names.txt",
  "wordlist2": "uploads/last-names.txt",
  "separator": "",
  "workers": 6
}
```

**Advanced Parameters:**
```json
{
  "algo": "bcrypt",
  "target": "$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW",
  "mode": "wordlist",
  "wordlist": "uploads/custom-wordlist.txt",
  "salt": "optional-salt-value",
  "workers": 8,
  "bcrypt_cost": 12,
  "scrypt_n": 32768, "scrypt_r": 8, "scrypt_p": 1,
  "argon_time": 1, "argon_mem_kb": 65536, "argon_par": 4
}
```
</details>

---

## Build from source (optional and not needed)
Requirements: Go 1.22+

```powershell
# Build CLI
go build -o bin/hashcrack ./cmd/hashcrack

# Run web locally
bin/hashcrack web --addr :8080
```

Environment overrides (via Viper): `HASHCRACK_WORKERS`, `HASHCRACK_LOG`, etc.

---

## Troubleshooting
- Default wordlist: the UI references `testdata/rockyou-mini.txt` included in this repository.
- Uploads: `.txt`/`.lst` files supported. Binary content is rejected.
- Paths: inside the container the repo is `/data`; use relative paths like `uploads/...`.
- Compose lifecycle: `docker compose down` to stop; `docker compose logs -f` to follow logs.

---
> Use ethically and legally. Only attack hashes you own or are authorized to test.

Developped with love by Zeph as part of my internship at GI.

