# WatchMeWhip — CCTV Monitoring System

Secure CCTV web application with login authentication, intrusion detection, and session logging. Built with Flask + PostgreSQL, deployable on Railway.

---

## Project Structure

```
├── app.py                  # Flask backend (auth, DB, intrusion detection)
├── templates/
│   └── index.html          # Full frontend (login + dashboard + logs)
├── static/
│   ├── login.css           # Styles
│   └── login.js            # Frontend logic (API calls)
├── requirements.txt
├── Procfile                # For Railway / gunicorn
├── railway.toml            # Railway config
└── README.md
```

---

## Features

- **Secure Login** — credentials verified against PostgreSQL users table
- **Session Logging** — every login/logout recorded with time, IP, user-agent
- **Intrusion Detection** — failed logins, invalid emails, brute-force attempts logged
- **Brute-Force Protection** — 5 failed attempts = 5-minute IP lockout
- **Dashboard** — camera feed simulation, system overview, activity log
- **Session Logs Page** — all login/logout sessions from DB
- **Intrusion Logs Page** — all suspicious/failed access attempts from DB

---

## Local Development

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Set environment variables
```bash
export DATABASE_URL="postgresql://user:password@host:5432/dbname"
export SECRET_KEY="your-secret-key-here"
```

### 3. Run
```bash
python app.py
```

---

## Railway Deployment

### Step 1 — Push your code to GitHub
Make sure your repo has all files including `Procfile` and `railway.toml`.

### Step 2 — Create a Railway project
1. Go to [railway.app](https://railway.app) and sign in
2. Click **New Project** → **Deploy from GitHub repo**
3. Select your repository

### Step 3 — Add PostgreSQL
1. In your Railway project, click **+ Add Service** → **Database** → **PostgreSQL**
2. Railway will automatically create a `DATABASE_URL` variable

### Step 4 — Set environment variables
In your Railway service settings, add:
```
SECRET_KEY=some-random-secret-string-here
```
`DATABASE_URL` is set automatically by Railway when you link the Postgres service.

### Step 5 — Deploy
Railway auto-deploys on every push to your linked branch. Tables are created automatically on first run.

---

## Default Login Credentials

```
Email:    group5@securewatch.com
Password: group5123
```

> **Important:** Change these in production! Update the seed in `app.py`'s `init_db()` function or insert a new user directly into the `users` table with a hashed password.

---

## Database Tables

| Table | Purpose |
|-------|---------|
| `users` | Admin accounts with hashed passwords |
| `session_logs` | Login/logout records (time in/out, IP, status) |
| `intrusion_logs` | Failed/suspicious access attempts |

---

## Intrusion Detection Triggers

The system logs an intrusion record when:
- Email format is invalid on login attempt
- Password is too short on login attempt  
- Credentials don't match any user account
- An IP exceeds 5 failed attempts (brute-force lockout)
