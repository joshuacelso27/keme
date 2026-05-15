import os
import re
import hashlib
from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify, session
import psycopg2
import psycopg2.extras

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'watchmewhip-secret-key-change-in-prod')

# ─── DATABASE ────────────────────────────────────────────────────────────────

def get_db():
    db_url = os.environ.get('DATABASE_URL')
    if not db_url:
        raise RuntimeError('DATABASE_URL environment variable not set.')
    if db_url.startswith('postgres://'):
        db_url = db_url.replace('postgres://', 'postgresql://', 1)
    return psycopg2.connect(db_url, cursor_factory=psycopg2.extras.RealDictCursor)


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'admin',
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS session_logs (
            id SERIAL PRIMARY KEY,
            user_email TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            time_in TIMESTAMPTZ DEFAULT NOW(),
            time_out TIMESTAMPTZ,
            date_label TEXT,
            status TEXT DEFAULT 'active'
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS intrusion_logs (
            id SERIAL PRIMARY KEY,
            attempted_email TEXT,
            ip_address TEXT,
            user_agent TEXT,
            reason TEXT,
            attempted_at TIMESTAMPTZ DEFAULT NOW()
        );
    """)

    cur.execute("SELECT COUNT(*) as cnt FROM users;")
    row = cur.fetchone()
    if row['cnt'] == 0:
        pw_hash = hashlib.sha256('group5123'.encode()).hexdigest()
        cur.execute(
            "INSERT INTO users (email, password_hash, role) VALUES (%s, %s, %s)",
            ('group5@securewatch.com', pw_hash, 'admin')
        )

    conn.commit()
    cur.close()
    conn.close()


# ─── HELPERS ─────────────────────────────────────────────────────────────────

def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()


def is_valid_email(email):
    return re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email or '') is not None


def get_client_ip():
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr


def log_intrusion(email, reason):
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO intrusion_logs (attempted_email, ip_address, user_agent, reason)
            VALUES (%s, %s, %s, %s)
        """, (email, get_client_ip(), request.headers.get('User-Agent', ''), reason))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f'[intrusion_log error] {e}')


_failed_attempts: dict = {}
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300


def check_brute_force(ip):
    now = datetime.now(timezone.utc).timestamp()
    attempts = _failed_attempts.get(ip, [])
    attempts = [t for t in attempts if now - t < LOCKOUT_SECONDS]
    _failed_attempts[ip] = attempts
    if len(attempts) >= MAX_ATTEMPTS:
        return True, 0
    return False, MAX_ATTEMPTS - len(attempts)


def record_failed(ip):
    now = datetime.now(timezone.utc).timestamp()
    _failed_attempts.setdefault(ip, []).append(now)


def clear_failed(ip):
    _failed_attempts.pop(ip, None)


# ─── ROUTES ──────────────────────────────────────────────────────────────────

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    ip = get_client_ip()
    ua = request.headers.get('User-Agent', '')

    if not is_valid_email(email):
        log_intrusion(email, 'Invalid email format on login attempt')
        return jsonify(success=False, field='email', message='Invalid email address.'), 400

    if len(password) < 6:
        log_intrusion(email, 'Password too short on login attempt')
        return jsonify(success=False, field='password', message='Password must be at least 6 characters.'), 400

    locked, remaining = check_brute_force(ip)
    if locked:
        log_intrusion(email, f'Brute-force lockout triggered from IP {ip}')
        return jsonify(
            success=False, field='email',
            message=f'Too many failed attempts. Try again in {LOCKOUT_SECONDS // 60} minutes.'
        ), 429

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()
    except Exception as e:
        print(f'[db error] {e}')
        return jsonify(success=False, message='Database error. Please try again.'), 500

    if not user or user['password_hash'] != hash_password(password):
        record_failed(ip)
        locked2, remaining2 = check_brute_force(ip)
        reason = 'Wrong credentials'
        if locked2:
            reason = f'Brute-force lockout after {MAX_ATTEMPTS} failed attempts'
        log_intrusion(email, reason)
        msg = 'Invalid credentials.'
        if remaining2 <= 2 and not locked2:
            msg += f' {remaining2} attempt(s) remaining before lockout.'
        return jsonify(success=False, field='email', message=msg), 401

    clear_failed(ip)
    now = datetime.now(timezone.utc)
    date_label = now.strftime('%B %d, %Y')
    time_in = now.strftime('%H:%M:%S')

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO session_logs (user_email, ip_address, user_agent, date_label, status)
            VALUES (%s, %s, %s, %s, 'active') RETURNING id
        """, (email, ip, ua, date_label))
        session_id = cur.fetchone()['id']
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f'[db error] {e}')
        session_id = None

    session['user_email'] = email
    session['session_log_id'] = session_id

    return jsonify(
        success=True,
        user=email,
        role=user['role'],
        timeIn=time_in,
        date=date_label,
        sessionId=session_id
    )


@app.route('/api/session', methods=['GET'])
def api_session():
    """Check if a valid server-side session exists — used on page refresh."""
    if 'user_email' not in session:
        return jsonify(success=False, message='No active session'), 401

    email = session['user_email']
    session_log_id = session.get('session_log_id')

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT role FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        time_in_str = None
        date_label_str = None
        if session_log_id:
            cur.execute("""
                SELECT TO_CHAR(time_in AT TIME ZONE 'UTC', 'HH24:MI:SS') AS time_in,
                       date_label
                FROM session_logs WHERE id = %s
            """, (session_log_id,))
            log_row = cur.fetchone()
            if log_row:
                time_in_str = log_row['time_in']
                date_label_str = log_row['date_label']

        cur.close()
        conn.close()
    except Exception as e:
        print(f'[db error] {e}')
        return jsonify(success=False, message='Database error'), 500

    if not user:
        session.clear()
        return jsonify(success=False, message='User not found'), 401

    now = datetime.now(timezone.utc)
    return jsonify(
        success=True,
        user=email,
        role=user['role'],
        timeIn=time_in_str or now.strftime('%H:%M:%S'),
        date=date_label_str or now.strftime('%B %d, %Y'),
        sessionId=session_log_id
    )


@app.route('/api/logout', methods=['POST'])
def api_logout():
    session_log_id = session.get('session_log_id')
    now = datetime.now(timezone.utc)

    if session_log_id:
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("""
                UPDATE session_logs
                SET time_out = %s, status = 'closed'
                WHERE id = %s
            """, (now, session_log_id))
            conn.commit()
            cur.close()
            conn.close()
        except Exception as e:
            print(f'[db error] {e}')

    session.clear()
    return jsonify(success=True, timeOut=now.strftime('%H:%M:%S'))


@app.route('/api/logs', methods=['GET'])
def api_logs():
    if 'user_email' not in session:
        return jsonify(success=False, message='Unauthorized'), 401

    try:
        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
            SELECT user_email, ip_address,
                   TO_CHAR(time_in AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') AS time_in,
                   TO_CHAR(time_out AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') AS time_out,
                   date_label, status
            FROM session_logs
            ORDER BY time_in DESC
            LIMIT 100
        """)
        sessions = [dict(r) for r in cur.fetchall()]

        cur.execute("""
            SELECT attempted_email, ip_address, reason,
                   TO_CHAR(attempted_at AT TIME ZONE 'UTC', 'HH24:MI:SS') AS time,
                   TO_CHAR(attempted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS date,
                   TO_CHAR(attempted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') AS full_datetime
            FROM intrusion_logs
            ORDER BY attempted_at DESC
            LIMIT 100
        """)
        intrusions = [dict(r) for r in cur.fetchall()]

        cur.close()
        conn.close()
    except Exception as e:
        print(f'[db error] {e}')
        return jsonify(success=False, message='Database error'), 500

    return jsonify(success=True, sessions=sessions, intrusions=intrusions)


# ─── STARTUP ─────────────────────────────────────────────────────────────────

with app.app_context():
    try:
        init_db()
        print('[DB] Tables initialized.')
    except Exception as e:
        print(f'[DB INIT ERROR] {e}')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
