<div align="center">

<!-- Logo placeholder - replace with your actual logo -->
![HashCrack Logo](docs/logo.png)

# HashCrack

**A high-performance, concurrent hash-cracking toolkit with comprehensive Web UI and CLI**

[![Go Version](https://img.shields.io/badge/Go-1.23%2B-00ADD8?style=flat-square&logo=go&logoColor=white)](https://golang.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker&logoColor=white)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-Educational-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?style=flat-square)](https://github.com/golang/go/wiki/MinimumRequirements)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Supported Algorithms](#supported-algorithms)
- [Attack Modes](#attack-modes)
- [Quick Start](#quick-start)
- [Web Interface](#web-interface)
- [CLI Usage](#cli-usage)
- [State Management & Resume](#state-management--resume)
- [API Reference](#api-reference)
- [Architecture](#architecture)
- [Build from Source](#build-from-source)


---

## Overview

HashCrack is a modern, Docker-first hash-cracking toolkit designed for cybersecurity education and authorized security testing. Built with Go for maximum performance, it provides both a user-friendly web interface and a powerful command-line interface for hash analysis and password recovery.

> **Key Design Principles**: Performance, usability, state persistence, and comprehensive algorithm support.

---

## Features

### **Performance & Scalability**
- **Concurrent processing** with optimized worker pools
- **Memory-efficient** algorithms with SIMD acceleration where available
- **Bounded resource usage** with configurable worker limits
- **Real-time progress tracking** with speed and ETA calculations

### **Attack Capabilities**
- **Six attack modes**: Dictionary, Mask, Brute Force, Combination, Hybrid, and Association
- **200+ hash algorithms** including legacy and modern cryptographic functions
- **Smart algorithm detection** with heuristic analysis
- **Rule-based transformations** for wordlist attacks

### **State Management**
- **Automatic checkpointing** for long-running operations
- **Resume capability** surviving system restarts and interruptions
- **Task persistence** with human-readable JSON state files
- **Pause/resume functionality** for optimal resource management

### **User Experience**
- **Modern web interface** with real-time updates via Server-Sent Events
- **Comprehensive CLI** for automation and scripting
- **File upload support** with validation and preprocessing
- **Cross-platform compatibility** via Docker containers

---

## Supported Algorithms

<details>
<summary><strong>Complete Algorithm List (200+ supported)</strong></summary>

### **Cryptographic Hash Functions**
- **MD Family**: `md4`, `md5`, `md6-256`
- **SHA Family**: `sha1`, `sha224`, `sha256`, `sha384`, `sha512`
- **SHA-3**: `sha3-224`, `sha3-256`, `sha3-384`, `sha3-512`
- **BLAKE**: `blake2b-256`, `blake2b-512`, `blake2s-256`
- **Other**: `ripemd160`, `whirlpool`, `keccac-*`, `shake128`, `shake256`

### **Key Derivation Functions**
- **PBKDF2**: `pbkdf2-hmac-md5`, `pbkdf2-hmac-sha1`, `pbkdf2-hmac-sha256`, `pbkdf2-hmac-sha512`
- **scrypt**: `scrypt` with configurable parameters
- **Argon2**: `argon2id` with time/memory/parallelism controls
- **bcrypt**: `bcrypt` with configurable cost factors

### **Application-Specific Formats**
- **Database**: `mysql`, `mysql323`, `mysql41`, `postgresql`, `oracle-*`, `mssql-*`
- **Operating Systems**: `ntlm`, `lm`, `macos-*`, `descrypt`, `sha256crypt`, `sha512crypt`
- **Network Equipment**: `cisco`, `cisco-*`, `juniper-*`, `fortigate*`
- **Applications**: `lotus-notes-*`, `adobe-*`, `wordpress`, `drupal7`

### **Enterprise & Legacy**
- **LDAP**: `ldap_md5`, `ldap_sha1`, `nsldap-*`, `ssha-*`
- **SAP**: `sap-codvn-*` series
- **Citrix**: `citrix-netscaler-*`
- **VMware**: Various VMware authentication schemes

### **Specialized & Research**
- **GOST**: `gost-94`, `gost-streebog-*`
- **SM**: `sm3`, `sm3crypt` (Chinese standards)
- **Checksums**: `crc32`, `crc32c`, `crc64jones`
- **Development**: `java-hashcode`, `murmurhash*`

> Run `hashcrack list` for the complete enumeration of all supported algorithms.

</details>

---

## Attack Modes

### 1. **Dictionary Attack**
*Most effective for common passwords*

Uses predefined wordlists with optional rule-based transformations.

```bash
# Basic dictionary attack
hashcrack crack -a md5 -h "5d41402abc4b2a76b9719d911017c592" -w wordlist.txt

# With transformation rules
hashcrack crack -a md5 -h "hash" -w wordlist.txt --rules "+c,+d2,+!"
```

**Features:**
- Built-in `rockyou-mini.txt` sample wordlist
- Support for custom wordlists (`.txt`/`.lst` format, ≤10MB)
- Rule transformations: `+c` (capitalize), `+d2` (append digits), `+!` (append symbols)

### 2. **Mask Attack**
*Targeted approach for known password patterns*

Uses placeholder patterns to generate candidates systematically.

```bash
# Pattern: 4 letters + 2 digits (e.g., "word12")
hashcrack crack -a sha1 -h "hash" -m "?l?l?l?l?d?d"
```

**Mask Characters:**
- `?l` = lowercase letters (a-z)
- `?u` = uppercase letters (A-Z)  
- `?d` = digits (0-9)
- `?s` = symbols (!@#$%^&*...)
- `?a` = all characters

### 3. **Brute Force Attack**
*Exhaustive search with configurable parameters*

Tries all possible combinations within specified constraints.

```bash
# Brute force with custom character set and length range
hashcrack crack -a md5 -h "hash" --bruteforce --bf-min 4 --bf-max 6 --bf-chars "abc123"
```

**Performance Warning**: Exponentially slow - recommended for passwords ≤6 characters.

### 4. **Combination Attack**
*Concatenates words from two wordlists*

Effective for compound passwords like "firstname_lastname".

```bash
# Combine two wordlists with optional separator
hashcrack combination -a md5 -h "hash" \
  --wordlist1 first-names.txt \
  --wordlist2 last-names.txt \
  --separator "_"
```

### 5. **Hybrid Attack**
*Combines dictionary words with mask patterns*

Two modes: append patterns to words or prepend patterns to words.

```bash
# Append 2 digits to dictionary words (e.g., "password12")
hashcrack hybrid -a sha256 -h "hash" -w wordlist.txt -m "?d?d"

# Prepend pattern to words (e.g., "12password")  
hashcrack hybrid -a sha256 -h "hash" -w wordlist.txt -m "?d?d" --prefix
```

### 6. **Association Attack**
*Context-aware candidate generation*

Generates passwords based on user/organizational context.

```bash
# Use personal/organizational context
hashcrack association -a md5 -h "hash" \
  --username "john.doe" \
  --email "john@company.com" \
  --company "TechCorp"
```

**Generated Patterns:**
- Username variations and common suffixes
- Email-based combinations  
- Company name derivatives
- Date and year combinations
- Common transformation rules

---

## Quick Start

### Prerequisites
- **Docker** and **Docker Compose** (recommended)
- **Go 1.23+** (for building from source)

### **Docker Deployment** (Recommended)

```bash
# 1. Clone the repository
git clone https://github.com/Zephkek/hashcrack
cd hashcrack

# 2. Start the application
docker compose up --build -d

# 3. Access the web interface
open http://localhost:8080

# 4. View logs (optional)
docker compose logs -f hashcrack
```

**Container Features:**
- Pre-built with all dependencies
- Optimized distroless runtime image
- Volume mounting for persistent data
- Automatic restart policies

### **Directory Structure**
```
hashcrack-main/
├── uploads/          # Custom wordlists (mounted volume)
├── states/           # Task state persistence
├── testdata/         # Built-in sample wordlists
└── web/              # Static web assets
```

---

## Web Interface

### **Modern Web UI**

<details>
<summary><strong>Interface Overview</strong></summary>

**Step-by-Step Workflow:**

1. **Hash Input**: Enter target hash with automatic algorithm detection
2. **Attack Mode Selection**: Choose from 6 attack modes with guided recommendations  
3. **Parameter Configuration**: Set workers, timeouts, and mode-specific options
4. **Real-time Monitoring**: Track progress with live updates and performance metrics
5. **Task Management**: Pause, resume, stop, and delete tasks with state persistence

</details>

**Key Features:**
- **Algorithm Detection**: Automatic suggestions based on hash format and length
- **File Upload**: Drag-and-drop wordlist uploads with validation
- **Real-time Updates**: Server-Sent Events for live progress tracking
- **State Visualization**: Task history and resume capabilities
- **Responsive Design**: Works on desktop and mobile devices

**Access**: http://localhost:8080 (default)

---

## CLI Usage

### **Command-Line Interface**

Run CLI commands inside the Docker container for proper path resolution:

```bash
# General syntax
docker compose exec hashcrack hashcrack [command] [options]
```

### **Core Commands**

```bash
# List all supported algorithms
docker compose exec hashcrack hashcrack list

# Algorithm detection for unknown hashes
docker compose exec hashcrack hashcrack detect "5d41402abc4b2a76b9719d911017c592"

# Start web server locally
docker compose exec hashcrack hashcrack web --addr :8080
```

### **Attack Examples**

<details>
<summary><strong>Dictionary Attack Examples</strong></summary>

```bash
# Basic wordlist attack
docker compose exec hashcrack hashcrack crack \
  -a md5 \
  -h "5d41402abc4b2a76b9719d911017c592" \
  -w uploads/wordlist.txt

# With rule transformations
docker compose exec hashcrack hashcrack crack \
  -a sha256 \
  -h "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3" \
  -w uploads/wordlist.txt \
  --rules "+c,+d2,+!"

# Using default wordlist
docker compose exec hashcrack hashcrack crack \
  -a md5 \
  -h "hash" \
  --default-wordlist
```

</details>

<details>
<summary><strong>Advanced Attack Examples</strong></summary>

```bash
# Mask attack with custom pattern
docker compose exec hashcrack hashcrack crack \
  -a sha1 \
  -h "356a192b7913b04c54574d18c28d46e6395428ab" \
  -m "?l?l?l?l?d?d"

# Combination attack
docker compose exec hashcrack hashcrack combination \
  -a md5 \
  -h "hash" \
  --wordlist1 uploads/first-names.txt \
  --wordlist2 uploads/last-names.txt \
  --separator ""

# Hybrid attack (wordlist + mask)
docker compose exec hashcrack hashcrack hybrid \
  -a sha256 \
  -h "hash" \
  -w uploads/wordlist.txt \
  -m "?d?d?d"

# Association attack with context
docker compose exec hashcrack hashcrack association \
  -a md5 \
  -h "hash" \
  --username "john.doe" \
  --email "john@company.com" \
  --company "TechCorp"
```

</details>

### **Global Options**

```bash
--workers 8              # Number of concurrent workers (default: CPU cores)
--timeout 30m            # Maximum runtime (default: unlimited)
--log crack.log          # Save detailed logs to file
--verbose                # Enable verbose output
--config config.yaml     # Use custom configuration file
```

### **Algorithm-Specific Parameters**

```bash
# bcrypt parameters
--bcrypt-cost 12

# scrypt parameters  
--scrypt-n 32768 --scrypt-r 8 --scrypt-p 1

# Argon2 parameters
--argon-time 1 --argon-memory 65536 --argon-parallelism 4

# PBKDF2 parameters
--pbkdf2-iterations 10000
```

---

## State Management & Resume

### **Automatic State Persistence**

HashCrack implements comprehensive state management for long-running operations:

**What Gets Saved:**
- **Progress tracking**: Current position and attempts tried
- **Task configuration**: Algorithm, target hash, attack parameters  
- **Timing information**: Runtime, pause/resume timestamps
- **Worker state**: Current candidates and search space position
- **File references**: Wordlist paths and validation checksums

**State File Format:**
```json
{
  "task_id": "abc123",
  "algorithm": "sha256", 
  "target": "hash",
  "mode": "wordlist",
  "progress": {
    "tried": 1500000,
    "total": 14344391,
    "current_position": 1500000,
    "last_candidate": "password123"
  },
  "timing": {
    "started_at": "2024-01-01T10:00:00Z",
    "total_runtime": 3600,
    "checkpoint_interval": 30
  }
}
```

### **Resume Scenarios**

1. **Manual Pause/Resume**: Via web UI or CLI signals
2. **Container Restart**: Automatic state recovery on startup  
3. **System Crash**: Recovery from last automatic checkpoint
4. **Network Interruption**: Web UI reconnection with state sync

**Checkpoint Strategy:**
- Automatic saves every 30 seconds during active operations
- Manual checkpoints on pause/stop commands
- Atomic write operations to prevent corruption
- Cleanup of obsolete state files on completion

---

## API Reference

### **REST API Endpoints**

<details>
<summary><strong>Core System APIs</strong></summary>

| Method | Endpoint | Description | Response |
|--------|----------|-------------|----------|
| `GET` | `/api/stats` | System statistics and performance metrics | JSON object with CPU, memory, goroutines |
| `GET` | `/api/algorithms` | Complete list of supported algorithms | JSON array of algorithm names |
| `GET` | `/api/detect?target=<hash>` | Algorithm detection for target hash | JSON object with suggestions and confidence |
| `GET` | `/api/events` | Server-Sent Events stream | Real-time task updates and system events |

</details>

<details>
<summary><strong>Task Management APIs</strong></summary>

| Method | Endpoint | Description | Request Body |
|--------|----------|-------------|--------------|
| `GET` | `/api/tasks` | List all tasks with status and progress | - |
| `POST` | `/api/tasks` | Create new cracking task | Task configuration JSON |
| `GET` | `/api/tasks/{id}` | Get specific task details | - |
| `POST` | `/api/tasks/{id}/pause` | Pause running task (saves state) | - |
| `POST` | `/api/tasks/{id}/resume` | Resume paused task from checkpoint | - |
| `POST` | `/api/tasks/{id}/stop` | Stop task and clean up resources | - |
| `DELETE` | `/api/tasks/{id}` | Delete task and associated state | - |

</details>

<details>
<summary><strong>File Management APIs</strong></summary>

| Method | Endpoint | Description | Request Format |
|--------|----------|-------------|----------------|
| `POST` | `/api/uploads` | Upload wordlist file | `multipart/form-data` with `file` field |
| `GET` | `/api/resumable` | List tasks available for resume | - |

</details>

### **Task Creation Examples**

<details>
<summary><strong>JSON Request Examples</strong></summary>

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
  "separator": "_",
  "workers": 6
}
```

**Hybrid Attack:**
```json
{
  "algo": "sha256",
  "target": "hash",
  "mode": "hybrid",
  "wordlist": "uploads/wordlist.txt",
  "mask": "?d?d?d",
  "hybrid_mode": "wordlist-mask",
  "workers": 8
}
```

**Association Attack:**
```json
{
  "algo": "md5", 
  "target": "hash",
  "mode": "association",
  "username": "john.doe",
  "email": "john@company.com",
  "company": "TechCorp",
  "workers": 4
}
```

</details>

---

## Architecture

### **System Design**

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web UI        │    │   REST API       │    │   CLI Interface │
│   (JavaScript)  │◄──►│   (Go HTTP)      │◄──►│   (Cobra)       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │   Task Manager   │
                       │   (Goroutines)   │
                       └──────────────────┘
                                │
                ┌───────────────┼───────────────┐
                ▼               ▼               ▼
        ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
        │   Cracker   │ │   Hashes    │ │   State     │
        │   Engine    │ │   Registry  │ │   Manager   │
        └─────────────┘ └─────────────┘ └─────────────┘
                ▼               ▼               ▼
        ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
        │   Worker    │ │   Algorithm │ │   JSON      │
        │   Pools     │ │   Impl.     │ │   Files     │ 
        └─────────────┘ └─────────────┘ └─────────────┘
```

### **Component Breakdown**

<details>
<summary><strong>Core Components</strong></summary>

**`cmd/hashcrack/`** - CLI entry point and command definitions
- Cobra-based command structure
- Configuration management via Viper
- Signal handling and graceful shutdown

**`internal/web/`** - HTTP server and task management
- REST API endpoints with JSON responses
- Server-Sent Events for real-time updates  
- Task lifecycle management and state persistence
- File upload handling with validation

**`internal/hashes/`** - Algorithm registry and implementations
- Modular hasher interface with 400+ implementations
- Algorithm detection heuristics
- Parameter validation for KDFs and complex algorithms

**`internal/cracker/`** - Core attack engine
- Worker pool management with bounded concurrency
- Attack mode implementations (dictionary, mask, etc.)
- Progress tracking and checkpoint management

**`pkg/`** - Reusable components
- `mask/` - Mask pattern generator and validator
- `bruteforce/` - Combinatorial generator with state
- `workerpool/` - Generic worker pool implementation

</details>

### **Performance Optimizations**

- **SIMD Acceleration**: MD5 and SHA-256 with vectorized implementations
- **Memory Pooling**: Reusable buffers to reduce GC pressure  
- **Batch Processing**: Grouped hash operations for cache efficiency
- **Worker Affinity**: CPU-aware worker distribution
- **Progressive Loading**: Streaming wordlist processing for large files

---

## Build from Source

### **Development Setup**

**Prerequisites:**
- Go 1.23+ with module support
- Git for source control

```bash
# Clone repository
git clone <repository-url>
cd hashcrack-main

# Install dependencies 
go mod tidy

# Build CLI binary
go build -o bin/hashcrack ./cmd/hashcrack

# Run tests
go test ./...

# Start web server locally
./bin/hashcrack web --addr :8080
```

### **Build Configuration**

<details>
<summary><strong>Build Options</strong></summary>

```bash
# Development build with debug symbols
go build -o hashcrack ./cmd/hashcrack

# Production build (optimized)
go build -ldflags="-s -w" -trimpath -o hashcrack ./cmd/hashcrack

# Cross-compilation examples
GOOS=windows GOARCH=amd64 go build -o hashcrack.exe ./cmd/hashcrack
GOOS=linux GOARCH=arm64 go build -o hashcrack-arm64 ./cmd/hashcrack
```

</details>

### **Environment Configuration**

Environment variables (via Viper):
- `HASHCRACK_WORKERS` - Default worker count
- `HASHCRACK_LOG` - Log file path  
- `HASHCRACK_CONFIG` - Configuration file path
- `HASHCRACK_ADDR` - Web server bind address

---

<div align="center">

**HashCrack** - Built with ❤️ by Mohamed Maatallah
