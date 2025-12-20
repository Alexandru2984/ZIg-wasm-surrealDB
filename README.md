# 🦎 Zig Task Manager

A **full-stack Task Manager** built entirely in Zig — backend, frontend logic, and WebAssembly.

![Dashboard Preview](docs/screenshot-dashboard.png)

## ✨ Features

- **Pure Zig Backend** — HTTP server with [Zap](https://github.com/zigzap/zap) framework
- **Zig → WebAssembly Frontend** — UI logic compiled to WASM
- **User Authentication** — Signup, login, logout with token-based sessions
- **Per-User Tasks** — Logged users' tasks stored on server
- **Anonymous Mode** — Tasks saved in localStorage for non-logged users
- **Modern Dark UI** — Glassmorphism, smooth animations, Zig-themed colors

## 📸 Screenshots

| Login Page | Logged In Dashboard |
|------------|---------------------|
| ![Login](docs/screenshot-login.png) | ![Dashboard](docs/screenshot-dashboard.png) |

## 🚀 Quick Start

### Prerequisites

- [Zig](https://ziglang.org/download/) 0.15.x or later

### Run

```bash
# Clone and run
git clone <your-repo>
cd zig-task-manager

# Build and start server
zig build run

# Open in browser
open http://localhost:9000
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Browser                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ index.html  │  │  style.css  │  │      app.js         │  │
│  │             │  │ (dark theme)│  │ (auth + localStorage)│  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│                          │                                   │
│                    ┌─────▼─────┐                            │
│                    │ app.wasm  │ ← Zig compiled to WASM     │
│                    └───────────┘                            │
└─────────────────────────────────────────────────────────────┘
                           │ HTTP
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Zig + Zap Server                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │   main.zig   │  │   auth.zig   │  │ Static File      │   │
│  │ (REST API)   │  │ (tokens)     │  │ Server           │   │
│  └──────────────┘  └──────────────┘  └──────────────────┘   │
│                                                              │
│  Endpoints:                                                  │
│  POST /api/auth/signup    POST /api/auth/login              │
│  GET  /api/auth/me        GET  /api/tasks                   │
│  POST /api/tasks          PUT  /api/tasks/:id               │
│  DELETE /api/tasks/:id                                       │
└─────────────────────────────────────────────────────────────┘
```

## 📁 Project Structure

```
zig-task-manager/
├── src/
│   ├── main.zig          # HTTP server, API routes
│   └── auth.zig          # Authentication (tokens, hashing)
├── frontend/
│   └── src/
│       └── main.zig      # WASM frontend logic
├── public/
│   ├── index.html        # UI structure
│   ├── style.css         # Dark theme styles
│   └── app.js            # JS bridge & auth handling
├── build.zig             # Build configuration
└── build.zig.zon         # Dependencies (Zap)
```

## 🔐 Authentication

| Feature | Implementation |
|---------|----------------|
| Password Hashing | FNV-1a with salt |
| Session Token | `user_id.timestamp_hex` format |
| Token Expiry | 7 days |
| Storage | `localStorage` in browser |

## 🗄️ Task Storage

| User State | Storage Location | Persistence |
|------------|------------------|-------------|
| **Logged in** | Server memory | Until server restart |
| **Anonymous** | Browser localStorage | Permanent (per browser) |

## 🛠️ Development

```bash
# Build only
zig build

# Build and run
zig build run

# The WASM file is auto-generated in public/app.wasm
```

## 📦 Dependencies

- **[Zap](https://github.com/zigzap/zap)** v0.11.0 — Blazingly fast Zig HTTP server

## 📄 License

MIT

---

<div align="center">
  Built with 🧡 in <b>Zig</b>
</div>
