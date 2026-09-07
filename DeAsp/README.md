# DeAsp

A Burp-style pentesting toolkit built specifically for ASP.NET applications — WebForms `__VIEWSTATE`/`__EVENTVALIDATION` decoding, MAC-bypass testing, ASP.NET AJAX (`UpdatePanel`) response parsing, and a param editor that separates real attack surface (user input) from ASP.NET's own noise.

- `backend/` — FastAPI service that parses requests, decodes ViewState, replays requests, and checks MAC validation
- `frontend/` — React/TypeScript/Tailwind UI
- `testapp/AspNetTarget/` — an intentionally vulnerable ASP.NET Core target app for testing DeAsp against (optional, not required to use DeAsp against real targets)

## Prerequisites

- **Python 3.11+**
- **Node.js 20+** and npm
- **.NET 10 SDK** — only needed if you want to run the local vulnerable test target (`testapp/`)

## Quick start

Two terminals — one for the backend, one for the frontend.

**1. Backend**

```bash
cd backend
pip install -r requirements.txt
# On Arch/externally-managed Python environments, add --break-system-packages
uvicorn main:app --host 0.0.0.0 --port 8000
```

**2. Frontend**

```bash
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173**. The Vite dev server proxies `/api/*` to the backend on port 8000 (see `frontend/vite.config.ts`), so no extra config is needed.

## Optional: run the vulnerable test target

`testapp/AspNetTarget` is a self-contained ASP.NET Core app with 30 intentionally vulnerable endpoints (ViewState tampering, XSS, IDOR, CSRF, SQLi, SSRF, LFI, CORS misconfig, and more) for exercising DeAsp end-to-end. See `curl http://localhost:7001/status` once running for the full endpoint list and test credentials.

```bash
cd testapp/AspNetTarget
dotnet publish -c Release --self-contained true -r linux-x64 -o publish
./publish/AspNetTarget
```

It listens on **http://localhost:7001** (plain HTTP — no TLS). Point DeAsp's **Fetch/Attack** or **Intercept** tab at it; since it's HTTP-only, use the **HTTP** scheme toggle in the Intercept tab (raw pasted requests default to HTTPS).

Rebuild after editing `Program.cs`:

```bash
dotnet build                                              # quick syntax/type check
dotnet publish -c Release --self-contained true -r linux-x64 -o publish
```

## Docker Compose (backend + frontend only)

```bash
docker compose up --build
```

Backend on `:8000`, frontend on `:5173` (proxies to backend internally — see `frontend/nginx.conf`). This does not include the test target app.

## Using DeAsp

- **Login tab** — enter a login page URL and credentials to grab a session cookie automatically; it's stored in the cookie jar (top-right) and reused across tabs.
- **Attack tab** — point at a form page URL; DeAsp fetches it, decodes any `__VIEWSTATE`, and shows only user-controllable params by default (toggle "Show all params" to see the ASP.NET system fields too). Edit and send.
- **Intercept tab** — paste a raw HTTP request (e.g. captured from a proxy). Handles GET query-string params and POST bodies, both editable. Use the **🔐 Test MAC Bypass** button to check whether ViewState MAC validation is actually enforced server-side.
- **ViewState tab** — standalone base64 ViewState decoder.
- Responses from ASP.NET AJAX (`UpdatePanel`) requests are parsed into their component parts and rendered in a sandboxed iframe so you can see the actual page change, with a passive XSS-pattern indicator on each part.
