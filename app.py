from flask import Flask, render_template, jsonify, request, redirect, url_for, session, send_from_directory, flash
import sqlite3
import time
import threading
import requests
import os
import re
import secrets
import json
import random
import logging
from datetime import datetime, timedelta
from functools import wraps

# CRITICAL: Import psycopg2 at TOP LEVEL for Render
try:
    import psycopg2
    import psycopg2.extras
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False
    print("WARNING: psycopg2 not available, using SQLite")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.permanent_session_lifetime = timedelta(days=30)

@app.before_request
def make_session_permanent():
    session.permanent = True

app.secret_key = os.environ.get("SECRET_KEY", "bible-app-secret-key-2024")
STATIC_DOMAIN = os.environ.get("STATIC_DOMAIN", "aibible.onrender.com")
PUBLIC_URL = os.environ.get("PUBLIC_URL", "https://aibible.onrender.com")
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
ADMIN_CODE = os.environ.get("ADMIN_CODE", "God Is All")
DATABASE_URL = os.environ.get('DATABASE_URL')

if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

db_path = os.path.join(os.path.dirname(__file__), "bible_ios.db")

def is_postgres():
    return POSTGRES_AVAILABLE and DATABASE_URL and ('postgresql' in DATABASE_URL)

def get_db():
    """Get database connection"""
    try:
        if is_postgres():
            conn = psycopg2.connect(DATABASE_URL, sslmode='require')
            return conn, 'postgres'
        else:
            conn = sqlite3.connect(db_path, timeout=20)
            conn.row_factory = sqlite3.Row
            return conn, 'sqlite'
    except Exception as e:
        logger.error(f"DB connection error: {e}")
        raise

def get_cursor(conn, db_type):
    """Get cursor with dict access"""
    if db_type == 'postgres':
        return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    else:
        return conn.cursor()

def db_execute(c, sql, params=(), db_type='sqlite'):
    """Execute SQL with param substitution"""
    if db_type == 'postgres':
        sql = sql.replace('?', '%s')
        if 'INSERT OR IGNORE' in sql:
            sql = sql.replace('INSERT OR IGNORE', 'INSERT')
            sql += ' ON CONFLICT DO NOTHING'
    c.execute(sql, params)
    return c

def init_db():
    """Initialize database with all tables"""
    conn = None
    try:
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        
        if db_type == 'postgres':
            # PostgreSQL tables
            c.execute('''CREATE TABLE IF NOT EXISTS verses 
                         (id SERIAL PRIMARY KEY, reference TEXT, text TEXT, 
                          translation TEXT, source TEXT, timestamp TEXT, book TEXT)''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS users 
                         (id SERIAL PRIMARY KEY, google_id TEXT UNIQUE, email TEXT, 
                          name TEXT, picture TEXT, created_at TEXT, is_admin INTEGER DEFAULT 0,
                          is_banned BOOLEAN DEFAULT FALSE, ban_expires_at TIMESTAMP, ban_reason TEXT, role TEXT DEFAULT 'user')''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS likes 
                         (id SERIAL PRIMARY KEY, user_id INTEGER, verse_id INTEGER, 
                          timestamp TEXT, UNIQUE(user_id, verse_id))''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS saves 
                         (id SERIAL PRIMARY KEY, user_id INTEGER, verse_id INTEGER, 
                          timestamp TEXT, UNIQUE(user_id, verse_id))''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS comments 
                         (id SERIAL PRIMARY KEY, user_id INTEGER, verse_id INTEGER,
                          text TEXT, timestamp TEXT, google_name TEXT, google_picture TEXT)''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS collections 
                         (id SERIAL PRIMARY KEY, user_id INTEGER, name TEXT, 
                          color TEXT, created_at TEXT)''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS verse_collections 
                         (id SERIAL PRIMARY KEY, collection_id INTEGER, verse_id INTEGER,
                          UNIQUE(collection_id, verse_id))''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS verse_sessions 
                         (id SERIAL PRIMARY KEY, verse_id INTEGER, session_id TEXT,
                          created_at TEXT, expires_at TEXT)''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS community_messages 
                         (id SERIAL PRIMARY KEY, user_id INTEGER, text TEXT, 
                          timestamp TEXT, google_name TEXT, google_picture TEXT)''')
            
            # Add missing columns
            c.execute("SELECT column_name FROM information_schema.columns WHERE table_name='users' AND column_name='is_banned'")
            if not c.fetchone():
                c.execute("ALTER TABLE users ADD COLUMN is_banned BOOLEAN DEFAULT FALSE")
                c.execute("ALTER TABLE users ADD COLUMN ban_expires_at TIMESTAMP")
                c.execute("ALTER TABLE users ADD COLUMN ban_reason TEXT")
                logger.info("Added ban columns to PostgreSQL")
            
            c.execute("SELECT column_name FROM information_schema.columns WHERE table_name='users' AND column_name='role'")
            if not c.fetchone():
                c.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
                logger.info("Added role column to PostgreSQL")
        else:
            # SQLite tables
            c.execute('''CREATE TABLE IF NOT EXISTS verses 
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, reference TEXT, text TEXT, 
                          translation TEXT, source TEXT, timestamp TEXT, book TEXT)''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS users 
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, google_id TEXT UNIQUE, email TEXT, 
                          name TEXT, picture TEXT, created_at TEXT, is_admin INTEGER DEFAULT 0,
                          is_banned INTEGER DEFAULT 0, ban_expires_at TEXT, ban_reason TEXT, role TEXT DEFAULT 'user')''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS likes 
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, verse_id INTEGER, 
                          timestamp TEXT, UNIQUE(user_id, verse_id))''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS saves 
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, verse_id INTEGER, 
                          timestamp TEXT, UNIQUE(user_id, verse_id))''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS comments 
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, verse_id INTEGER,
                          text TEXT, timestamp TEXT, google_name TEXT, google_picture TEXT)''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS collections 
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT, 
                          color TEXT, created_at TEXT)''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS verse_collections 
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, collection_id INTEGER, verse_id INTEGER,
                          UNIQUE(collection_id, verse_id))''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS verse_sessions 
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, verse_id INTEGER, session_id TEXT,
                          created_at TEXT, expires_at TEXT)''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS community_messages 
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, text TEXT, 
                          timestamp TEXT, google_name TEXT, google_picture TEXT)''')
        
        conn.commit()
        logger.info(f"Database initialized ({db_type})")
    except Exception as e:
        logger.error(f"DB init error: {e}")
        raise
    finally:
        if conn:
            conn.close()

init_db()

def check_ban_status(user_id):
    """Check if user is banned - CRITICAL FUNCTION"""
    if not user_id:
        return False, None, None
    
    conn = None
    try:
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        
        if db_type == 'postgres':
            c.execute("SELECT is_banned, ban_expires_at, ban_reason FROM users WHERE id = %s", (user_id,))
        else:
            c.execute("SELECT is_banned, ban_expires_at, ban_reason FROM users WHERE id = ?", (user_id,))
        
        row = c.fetchone()
        
        if not row:
            return False, None, None
        
        if isinstance(row, dict):
            is_banned_raw = row.get('is_banned', False)
            expires = row.get('ban_expires_at')
            reason = row.get('ban_reason')
        else:
            is_banned_raw = row[0]
            expires = row[1] if len(row) > 1 else None
            reason = row[2] if len(row) > 2 else None
        
        # Normalize boolean
        if isinstance(is_banned_raw, bool):
            is_banned = is_banned_raw
        elif isinstance(is_banned_raw, int):
            is_banned = bool(is_banned_raw)
        elif isinstance(is_banned_raw, str):
            is_banned = is_banned_raw.lower() in ('true', 't', '1', 'yes')
        else:
            is_banned = False
        
        # Check expiry
        if is_banned and expires:
            try:
                if isinstance(expires, str):
                    expires = expires.replace('Z', '+00:00')
                    if '+' in expires:
                        expires_dt = datetime.fromisoformat(expires).replace(tzinfo=None)
                    else:
                        expires_dt = datetime.fromisoformat(expires)
                else:
                    expires_dt = expires
                
                if datetime.now() > expires_dt:
                    # Auto unban
                    if db_type == 'postgres':
                        c.execute("UPDATE users SET is_banned = FALSE, ban_expires_at = NULL, ban_reason = NULL WHERE id = %s", (user_id,))
                    else:
                        c.execute("UPDATE users SET is_banned = 0, ban_expires_at = NULL, ban_reason = NULL WHERE id = ?", (user_id,))
                    conn.commit()
                    return False, None, None
            except Exception as e:
                logger.error(f"Ban expiry check error: {e}")
        
        return is_banned, reason, expires
        
    except Exception as e:
        logger.error(f"Ban check error: {e}")
        return False, None, None
    finally:
        if conn:
            conn.close()

# GLOBAL BAN CHECK
@app.before_request
def global_ban_check():
    """Check ban status before every request"""
    if request.endpoint in ['static', 'serve_audio', 'manifest', 'login', 'callback', 'google_login']:
        return
    
    if 'user_id' not in session:
        return
    
    is_banned, reason, expires = check_ban_status(session['user_id'])
    
    if is_banned:
        logger.warning(f"Banned user {session['user_id']} attempted to access {request.path}")
        
        if expires:
            expires_str = expires[:16] if isinstance(expires, str) else expires.strftime('%Y-%m-%d %H:%M')
            msg = f'Banned until {expires_str}. Reason: {reason or "Violation"}'
        else:
            msg = f'Permanently banned. Reason: {reason or "Violation"}'
        
        session.clear()
        
        if request.path.startswith('/api/'):
            return jsonify({"error": msg, "banned": True}), 403
        
        flash(f'🚫 {msg}', 'error')
        return redirect(url_for('login'))

class BibleGenerator:
    def __init__(self):
        self.running = True
        self.interval = 60
        self.current_verse = {
            "id": 1,
            "ref": "John 3:16",
            "text": "For God so loved the world that he gave his one and only Son, that whoever believes in him shall not perish but have eternal life.",
            "trans": "NIV",
            "source": "Default",
            "book": "John",
            "is_new": True,
            "session_id": secrets.token_hex(8)
        }
        self.total_verses = 1
        self.session_id = secrets.token_hex(8)
        
        self.networks = [
            {"name": "Bible-API.com", "url": "https://bible-api.com/?random=verse"},
            {"name": "labs.bible.org", "url": "https://labs.bible.org/api/?passage=random&type=json"},
            {"name": "KJV Random", "url": "https://bible-api.com/?random=verse&translation=kjv"}
        ]
        self.network_idx = 0
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        self.last_fetch = time.time()
    
    def set_interval(self, seconds):
        self.interval = max(30, min(300, int(seconds)))
    
    def get_time_left(self):
        return max(0, self.interval - int(time.time() - self.last_fetch))
    
    def check_and_update(self):
        if time.time() - self.last_fetch > self.interval:
            self.fetch_verse()
    
    def extract_book(self, ref):
        match = re.match(r'^([0-9]?\s?[A-Za-z]+)', ref)
        return match.group(1) if match else "Unknown"
    
    def fetch_verse(self):
        self.last_fetch = time.time()
        network = self.networks[self.network_idx]
        try:
            r = self.session.get(network["url"], timeout=5)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list):
                    data = data[0]
                    ref = f"{data['bookname']} {data['chapter']}:{data['verse']}"
                    text = data['text']
                    trans = "WEB"
                else:
                    ref = data.get('reference', 'Unknown')
                    text = data.get('text', '').strip()
                    trans = data.get('translation_name', 'KJV')
                
                book = self.extract_book(ref)
                
                conn, db_type = get_db()
                c = get_cursor(conn, db_type)
                
                if db_type == 'postgres':
                    c.execute("""
                        INSERT INTO verses (reference, text, translation, source, timestamp, book) 
                        VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING
                    """, (ref, text, trans, network["name"], datetime.now().isoformat(), book))
                    c.execute("SELECT id FROM verses WHERE reference = %s AND text = %s", (ref, text))
                else:
                    c.execute("""
                        INSERT OR IGNORE INTO verses (reference, text, translation, source, timestamp, book) 
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (ref, text, trans, network["name"], datetime.now().isoformat(), book))
                    c.execute("SELECT id FROM verses WHERE reference = ? AND text = ?", (ref, text))
                
                result = c.fetchone()
                verse_id = result[0] if result else None
                conn.commit()
                conn.close()
                
                self.session_id = secrets.token_hex(8)
                self.current_verse = {
                    "id": verse_id, "ref": ref, "text": text,
                    "trans": trans, "source": network["name"], "book": book,
                    "is_new": True, "session_id": self.session_id
                }
                self.total_verses += 1
                return True
        except Exception as e:
            logger.error(f"Fetch error: {e}")
        
        self.network_idx = (self.network_idx + 1) % len(self.networks)
        return False
    
    def generate_smart_recommendation(self, user_id):
        try:
            conn, db_type = get_db()
            c = get_cursor(conn, db_type)
            
            if db_type == 'postgres':
                c.execute("""
                    SELECT DISTINCT v.book FROM verses v 
                    JOIN likes l ON v.id = l.verse_id WHERE l.user_id = %s
                    UNION
                    SELECT DISTINCT v.book FROM verses v 
                    JOIN saves s ON v.id = s.verse_id WHERE s.user_id = %s
                """, (user_id, user_id))
            else:
                c.execute("""
                    SELECT DISTINCT v.book FROM verses v 
                    JOIN likes l ON v.id = l.verse_id WHERE l.user_id = ?
                    UNION
                    SELECT DISTINCT v.book FROM verses v 
                    JOIN saves s ON v.id = s.verse_id WHERE s.user_id = ?
                """, (user_id, user_id))
            
            rows = c.fetchall()
            preferred_books = [row[0] if not isinstance(row, dict) else row['book'] for row in rows]
            
            if preferred_books:
                if db_type == 'postgres':
                    placeholders = ','.join(['%s'] * len(preferred_books))
                    c.execute(f"""
                        SELECT * FROM verses WHERE book IN ({placeholders})
                        AND id NOT IN (SELECT verse_id FROM likes WHERE user_id = %s)
                        ORDER BY RANDOM() LIMIT 1
                    """, (*preferred_books, user_id))
                else:
                    placeholders = ','.join('?' for _ in preferred_books)
                    c.execute(f"""
                        SELECT * FROM verses WHERE book IN ({placeholders})
                        AND id NOT IN (SELECT verse_id FROM likes WHERE user_id = ?)
                        ORDER BY RANDOM() LIMIT 1
                    """, (*preferred_books, user_id))
            else:
                if db_type == 'postgres':
                    c.execute("""
                        SELECT * FROM verses 
                        WHERE id NOT IN (SELECT verse_id FROM likes WHERE user_id = %s)
                        ORDER BY RANDOM() LIMIT 1
                    """, (user_id,))
                else:
                    c.execute("""
                        SELECT * FROM verses 
                        WHERE id NOT IN (SELECT verse_id FROM likes WHERE user_id = ?)
                        ORDER BY RANDOM() LIMIT 1
                    """, (user_id,))
            
            row = c.fetchone()
            conn.close()
            
            if row:
                if isinstance(row, dict):
                    return {
                        "id": row['id'], "ref": row['reference'], "text": row['text'],
                        "trans": row['translation'], "book": row['book'],
                        "reason": f"Because you like {row['book']}" if preferred_books else "Recommended for you"
                    }
                else:
                    return {
                        "id": row[0], "ref": row[1], "text": row[2],
                        "trans": row[3], "book": row[6],
                        "reason": f"Because you like {row[6]}" if preferred_books else "Recommended for you"
                    }
        except Exception as e:
            logger.error(f"Recommendation error: {e}")
        return None

generator = BibleGenerator()

@app.route('/static/audio/<path:filename>')
def serve_audio(filename):
    return send_from_directory(os.path.join(app.root_path, 'static', 'audio'), filename)

@app.route('/manifest.json')
def manifest():
    return jsonify({
        "name": "Bible AI",
        "short_name": "BibleAI",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#000000",
        "theme_color": "#0A84FF",
        "icons": [{"src": "/static/icon.png", "sizes": "192x192"}]
    })

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        
        if db_type == 'postgres':
            c.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
        else:
            c.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
        
        user = c.fetchone()
        
        if not user:
            session.clear()
            conn.close()
            return redirect(url_for('login'))
        
        # Extract user data
        if isinstance(user, dict):
            user_data = {
                'id': user['id'], 'email': user['email'], 'name': user['name'],
                'picture': user['picture'], 'is_admin': bool(user.get('is_admin', 0)),
                'is_banned': bool(user.get('is_banned', False)),
                'ban_reason': user.get('ban_reason'),
                'ban_expires_at': user.get('ban_expires_at')
            }
        else:
            user_data = {
                'id': user[0], 'email': user[2], 'name': user[3], 'picture': user[4],
                'is_admin': bool(user[6]) if len(user) > 6 else False,
                'is_banned': bool(user[7]) if len(user) > 7 else False,
                'ban_reason': user[8] if len(user) > 8 else None,
                'ban_expires_at': user[9] if len(user) > 9 else None
            }
        
        # Get stats
        c.execute("SELECT COUNT(*) FROM verses")
        total_verses = c.fetchone()
        total_verses = total_verses[0] if not isinstance(total_verses, dict) else total_verses.get('count', 0)
        
        if db_type == 'postgres':
            c.execute("SELECT COUNT(*) FROM likes WHERE user_id = %s", (session['user_id'],))
            liked_count = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM saves WHERE user_id = %s", (session['user_id'],))
            saved_count = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM comments WHERE user_id = %s", (session['user_id'],))
            comment_count = c.fetchone()[0]
        else:
            c.execute("SELECT COUNT(*) FROM likes WHERE user_id = ?", (session['user_id'],))
            liked_count = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM saves WHERE user_id = ?", (session['user_id'],))
            saved_count = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM comments WHERE user_id = ?", (session['user_id'],))
            comment_count = c.fetchone()[0]
        
        conn.close()
        
        return render_template('web.html', 
                             user=user_data,
                             stats={"total_verses": total_verses, "liked": liked_count, "saved": saved_count, "comments": comment_count})
    except Exception as e:
        logger.error(f"Index error: {e}")
        return f"Server Error: {str(e)}", 500

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/google-login')
def google_login():
    try:
        if not GOOGLE_CLIENT_ID:
            return "Google OAuth not configured", 500
            
        google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
        authorization_endpoint = google_provider_cfg["authorization_endpoint"]
        callback_url = PUBLIC_URL + "/callback"
        state = secrets.token_urlsafe(16)
        session['oauth_state'] = state
        
        auth_url = (
            f"{authorization_endpoint}"
            f"?client_id={GOOGLE_CLIENT_ID}"
            f"&redirect_uri={callback_url}"
            f"&response_type=code"
            f"&scope=openid%20email%20profile"
            f"&state={state}"
        )
        return redirect(auth_url)
    except Exception as e:
        logger.error(f"Login error: {e}")
        return f"Error: {str(e)}", 500

@app.route('/callback')
def callback():
    code = request.args.get("code")
    error = request.args.get("error")
    state = request.args.get("state")
    
    if error:
        return f"OAuth Error: {error}", 400
    if not code:
        return "No authorization code", 400
    if state != session.get('oauth_state'):
        return "Invalid state", 400
    
    try:
        google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
        token_endpoint = google_provider_cfg["token_endpoint"]
        callback_url = PUBLIC_URL + "/callback"
        
        token_response = requests.post(
            token_endpoint,
            data={
                "code": code,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": callback_url,
                "grant_type": "authorization_code",
            },
        )
        
        if not token_response.ok:
            return f"Token error: {token_response.text}", 400
        
        tokens = token_response.json()
        access_token = tokens.get("access_token")
        
        userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
        userinfo_response = requests.get(
            userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        if not userinfo_response.ok:
            return "Failed to get user info", 400
        
        userinfo = userinfo_response.json()
        google_id = userinfo['sub']
        email = userinfo['email']
        name = userinfo.get('name', email.split('@')[0])
        picture = userinfo.get('picture', '')
        
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        
        if db_type == 'postgres':
            c.execute("SELECT * FROM users WHERE google_id = %s", (google_id,))
        else:
            c.execute("SELECT * FROM users WHERE google_id = ?", (google_id,))
        
        user = c.fetchone()
        
        if not user:
            if db_type == 'postgres':
                c.execute("""
                    INSERT INTO users (google_id, email, name, picture, created_at, is_admin, is_banned, role) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING
                """, (google_id, email, name, picture, datetime.now().isoformat(), 0, False, 'user'))
            else:
                c.execute("""
                    INSERT OR IGNORE INTO users (google_id, email, name, picture, created_at, is_admin, is_banned, role) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (google_id, email, name, picture, datetime.now().isoformat(), 0, 0, 'user'))
            conn.commit()
            
            if db_type == 'postgres':
                c.execute("SELECT * FROM users WHERE google_id = %s", (google_id,))
            else:
                c.execute("SELECT * FROM users WHERE google_id = ?", (google_id,))
            user = c.fetchone()
        
        # Extract user data
        if isinstance(user, dict):
            user_id = user['id']
            is_banned = bool(user.get('is_banned', False))
            ban_expires = user.get('ban_expires_at')
            ban_reason = user.get('ban_reason')
            is_admin = bool(user.get('is_admin', 0))
        else:
            user_id = user[0]
            is_banned = bool(user[7]) if len(user) > 7 else False
            ban_expires = user[8] if len(user) > 8 else None
            ban_reason = user[9] if len(user) > 9 else None
            is_admin = bool(user[6]) if len(user) > 6 else False
        
        # Check ban expiry
        if is_banned and ban_expires:
            try:
                if isinstance(ban_expires, str):
                    expires_dt = datetime.fromisoformat(ban_expires.replace('Z', '+00:00').replace('+00:00', ''))
                else:
                    expires_dt = ban_expires
                
                if datetime.now() > expires_dt:
                    if db_type == 'postgres':
                        c.execute("UPDATE users SET is_banned = FALSE, ban_expires_at = NULL, ban_reason = NULL WHERE id = %s", (user_id,))
                    else:
                        c.execute("UPDATE users SET is_banned = 0, ban_expires_at = NULL, ban_reason = NULL WHERE id = ?", (user_id,))
                    conn.commit()
                    is_banned = False
            except:
                pass
        
        if is_banned:
            conn.close()
            if ban_expires:
                if isinstance(ban_expires, str):
                    expires_str = ban_expires[:16]
                else:
                    expires_str = ban_expires.strftime('%Y-%m-%d %H:%M')
                return f"""
                <html><body style="text-align:center;padding:50px; background:#1a1a2e; color:white;">
                    <h1>🚫 Account Suspended</h1>
                    <p>Until: {expires_str}</p>
                    <p>Reason: {ban_reason or 'Violation'}</p>
                </body></html>
                """, 403
            else:
                return f"""
                <html><body style="text-align:center;padding:50px; background:#1a1a2e; color:white;">
                    <h1>🚫 Permanently Banned</h1>
                    <p>Reason: {ban_reason or 'Violation'}</p>
                </body></html>
                """, 403
        
        conn.close()
        session['user_id'] = user_id
        session['user_name'] = name
        session['user_picture'] = picture
        session['is_admin'] = is_admin
        return redirect(url_for('index'))
    except Exception as e:
        logger.error(f"Callback error: {e}")
        return f"Authentication error: {str(e)}", 500   

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/current')
def get_current():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    try:
        generator.check_and_update()
        return jsonify({
            "verse": generator.current_verse,
            "countdown": generator.get_time_left(),
            "total_verses": generator.total_verses,
            "session_id": generator.session_id,
            "interval": generator.interval
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/set_interval', methods=['POST'])
def set_interval():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    if not session.get('is_admin'):
        return jsonify({"error": "Admin required"}), 403
    
    data = request.get_json()
    interval = data.get('interval', 60)
    generator.set_interval(interval)
    return jsonify({"success": True, "interval": generator.interval})

@app.route('/api/user_info')
def get_user_info():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    try:
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        
        if db_type == 'postgres':
            c.execute("SELECT created_at, is_admin, is_banned, ban_expires_at, ban_reason FROM users WHERE id = %s", (session['user_id'],))
        else:
            c.execute("SELECT created_at, is_admin, is_banned, ban_expires_at, ban_reason FROM users WHERE id = ?", (session['user_id'],))
        
        row = c.fetchone()
        conn.close()
        
        if row:
            if isinstance(row, dict):
                return jsonify({
                    "created_at": row['created_at'],
                    "is_admin": bool(row.get('is_admin', 0)),
                    "is_banned": bool(row.get('is_banned', False)),
                    "ban_reason": row.get('ban_reason'),
                    "ban_expires_at": row.get('ban_expires_at')
                })
            else:
                return jsonify({
                    "created_at": row[0],
                    "is_admin": bool(row[1]) if len(row) > 1 else False,
                    "is_banned": bool(row[2]) if len(row) > 2 else False,
                    "ban_reason": row[3] if len(row) > 3 else None,
                    "ban_expires_at": row[4] if len(row) > 4 else None
                })
        return jsonify({})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/verify_admin', methods=['POST'])
def verify_admin():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    data = request.get_json()
    code = data.get('code', '')
    
    if code == ADMIN_CODE:
        try:
            conn, db_type = get_db()
            c = get_cursor(conn, db_type)
            
            if db_type == 'postgres':
                c.execute("UPDATE users SET is_admin = 1 WHERE id = %s", (session['user_id'],))
            else:
                c.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (session['user_id'],))
            conn.commit()
            conn.close()
            
            session['is_admin'] = True
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)})
    else:
        return jsonify({"success": False, "error": "Wrong code"})

@app.route('/api/stats')
def get_stats():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    try:
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        
        c.execute("SELECT COUNT(*) FROM verses")
        row = c.fetchone()
        total = row[0] if not isinstance(row, dict) else row.get('count', 0)
        
        if db_type == 'postgres':
            c.execute("SELECT COUNT(*) FROM likes WHERE user_id = %s", (session['user_id'],))
            liked = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM saves WHERE user_id = %s", (session['user_id'],))
            saved = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM comments WHERE user_id = %s", (session['user_id'],))
            comments = c.fetchone()[0]
        else:
            c.execute("SELECT COUNT(*) FROM likes WHERE user_id = ?", (session['user_id'],))
            liked = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM saves WHERE user_id = ?", (session['user_id'],))
            saved = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM comments WHERE user_id = ?", (session['user_id'],))
            comments = c.fetchone()[0]
        
        conn.close()
        return jsonify({"total_verses": total, "liked": liked, "saved": saved, "comments": comments})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/like', methods=['POST'])
def like_verse():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    is_banned, _, _ = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "You are banned", "banned": True}), 403
    
    try:
        data = request.get_json()
        verse_id = data.get('verse_id')
        
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        
        if db_type == 'postgres':
            c.execute("SELECT id FROM likes WHERE user_id = %s AND verse_id = %s", (session['user_id'], verse_id))
            if c.fetchone():
                c.execute("DELETE FROM likes WHERE user_id = %s AND verse_id = %s", (session['user_id'], verse_id))
                liked = False
            else:
                c.execute("INSERT INTO likes (user_id, verse_id, timestamp) VALUES (%s, %s, %s)",
                          (session['user_id'], verse_id, datetime.now().isoformat()))
                liked = True
        else:
            c.execute("SELECT id FROM likes WHERE user_id = ? AND verse_id = ?", (session['user_id'], verse_id))
            if c.fetchone():
                c.execute("DELETE FROM likes WHERE user_id = ? AND verse_id = ?", (session['user_id'], verse_id))
                liked = False
            else:
                c.execute("INSERT INTO likes (user_id, verse_id, timestamp) VALUES (?, ?, ?)",
                          (session['user_id'], verse_id, datetime.now().isoformat()))
                liked = True
        
        conn.commit()
        conn.close()
        
        if liked:
            rec = generator.generate_smart_recommendation(session['user_id'])
            return jsonify({"liked": liked, "recommendation": rec})
        
        return jsonify({"liked": liked})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/save', methods=['POST'])
def save_verse():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    is_banned, _, _ = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "You are banned", "banned": True}), 403
    
    try:
        data = request.get_json()
        verse_id = data.get('verse_id')
        
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        
        if db_type == 'postgres':
            c.execute("SELECT id FROM saves WHERE user_id = %s AND verse_id = %s", (session['user_id'], verse_id))
            if c.fetchone():
                c.execute("DELETE FROM saves WHERE user_id = %s AND verse_id = %s", (session['user_id'], verse_id))
                saved = False
            else:
                c.execute("INSERT INTO saves (user_id, verse_id, timestamp) VALUES (%s, %s, %s)",
                          (session['user_id'], verse_id, datetime.now().isoformat()))
                saved = True
        else:
            c.execute("SELECT id FROM saves WHERE user_id = ? AND verse_id = ?", (session['user_id'], verse_id))
            if c.fetchone():
                c.execute("DELETE FROM saves WHERE user_id = ? AND verse_id = ?", (session['user_id'], verse_id))
                saved = False
            else:
                c.execute("INSERT INTO saves (user_id, verse_id, timestamp) VALUES (?, ?, ?)",
                          (session['user_id'], verse_id, datetime.now().isoformat()))
                saved = True
        
        conn.commit()
        conn.close()
        return jsonify({"saved": saved})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/library')
def get_library():
    if 'user_id' not in session:
        return jsonify({"liked": [], "saved": [], "collections": []})
    
    try:
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        
        if db_type == 'postgres':
            c.execute("""
                SELECT v.id, v.reference, v.text, v.translation, v.source, v.book, l.timestamp as liked_at
                FROM verses v JOIN likes l ON v.id = l.verse_id WHERE l.user_id = %s ORDER BY l.timestamp DESC
            """, (session['user_id'],))
        else:
            c.execute("""
                SELECT v.id, v.reference, v.text, v.translation, v.source, v.book, l.timestamp as liked_at
                FROM verses v JOIN likes l ON v.id = l.verse_id WHERE l.user_id = ? ORDER BY l.timestamp DESC
            """, (session['user_id'],))
        liked_rows = c.fetchall()
        
        if db_type == 'postgres':
            c.execute("""
                SELECT v.id, v.reference, v.text, v.translation, v.source, v.book, s.timestamp as saved_at
                FROM verses v JOIN saves s ON v.id = s.verse_id WHERE s.user_id = %s ORDER BY s.timestamp DESC
            """, (session['user_id'],))
        else:
            c.execute("""
                SELECT v.id, v.reference, v.text, v.translation, v.source, v.book, s.timestamp as saved_at
                FROM verses v JOIN saves s ON v.id = s.verse_id WHERE s.user_id = ? ORDER BY s.timestamp DESC
            """, (session['user_id'],))
        saved_rows = c.fetchall()
        
        def row_to_dict(row):
            if isinstance(row, dict):
                return {'id': row['id'], 'ref': row['reference'], 'text': row['text'], 
                       'trans': row['translation'], 'source': row['source'], 'book': row['book']}
            return {'id': row[0], 'ref': row[1], 'text': row[2], 
                   'trans': row[3], 'source': row[4], 'book': row[5]}
        
        liked = [row_to_dict(row) for row in liked_rows]
        saved = [row_to_dict(row) for row in saved_rows]
        
        conn.close()
        return jsonify({"liked": liked, "saved": saved, "collections": []})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/comments/<int:verse_id>')
def get_comments(verse_id):
    try:
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        
        if db_type == 'postgres':
            c.execute("""
                SELECT c.*, u.name, u.picture FROM comments c
                JOIN users u ON c.user_id = u.id WHERE c.verse_id = %s ORDER BY c.timestamp DESC
            """, (verse_id,))
        else:
            c.execute("""
                SELECT c.*, u.name, u.picture FROM comments c
                JOIN users u ON c.user_id = u.id WHERE c.verse_id = ? ORDER BY c.timestamp DESC
            """, (verse_id,))
        
        rows = c.fetchall()
        conn.close()
        
        comments = []
        for row in rows:
            if isinstance(row, dict):
                comments.append({
                    "id": row['id'], "text": row['text'], "timestamp": row['timestamp'],
                    "user_name": row['name'], "user_picture": row['picture']
                })
            else:
                comments.append({
                    "id": row[0], "text": row[3], "timestamp": row[4],
                    "user_name": row[7], "user_picture": row[8]
                })
        
        return jsonify(comments)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/comments', methods=['POST'])
def post_comment():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    is_banned, reason, expires = check_ban_status(session['user_id'])
    if is_banned:
        if expires:
            expires_str = expires[:16] if isinstance(expires, str) else expires.strftime('%Y-%m-%d %H:%M')
            msg = f'You are banned until {expires_str}. Reason: {reason or "Violation"}'
        else:
            msg = f'You are permanently banned. Reason: {reason or "Violation"}'
        return jsonify({"error": msg, "banned": True}), 403
    
    try:
        data = request.get_json()
        verse_id = data.get('verse_id')
        text = data.get('text', '').strip()
        
        if not text:
            return jsonify({"error": "Empty comment"}), 400
        
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        
        if db_type == 'postgres':
            c.execute("""
                INSERT INTO comments (user_id, verse_id, text, timestamp, google_name, google_picture) 
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (session['user_id'], verse_id, text, datetime.now().isoformat(), 
                   session.get('user_name'), session.get('user_picture')))
        else:
            c.execute("""
                INSERT INTO comments (user_id, verse_id, text, timestamp, google_name, google_picture) 
                VALUES (?, ?, ?, ?, ?, ?)
            """, (session['user_id'], verse_id, text, datetime.now().isoformat(), 
                   session.get('user_name'), session.get('user_picture')))
        
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/delete_comment/<int:comment_id>', methods=['DELETE'])
def delete_comment(comment_id):
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    if not session.get('is_admin'):
        return jsonify({"error": "Admin required"}), 403
    
    try:
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        
        if db_type == 'postgres':
            c.execute("DELETE FROM comments WHERE id = %s", (comment_id,))
        else:
            c.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
        
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/community')
def get_community_messages():
    try:
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        
        c.execute("""
            SELECT m.*, u.name, u.picture FROM community_messages m
            JOIN users u ON m.user_id = u.id ORDER BY m.timestamp DESC LIMIT 100
        """)
        
        rows = c.fetchall()
        conn.close()
        
        messages = []
        for row in rows:
            if isinstance(row, dict):
                messages.append({
                    "id": row['id'], "text": row['text'], "timestamp": row['timestamp'],
                    "user_name": row['name'], "user_picture": row['picture']
                })
            else:
                messages.append({
                    "id": row[0], "text": row[2], "timestamp": row[3],
                    "user_name": row[6], "user_picture": row[7]
                })
        
        return jsonify(messages)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/community', methods=['POST'])
def post_community_message():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    is_banned, reason, expires = check_ban_status(session['user_id'])
    if is_banned:
        if expires:
            expires_str = expires[:16] if isinstance(expires, str) else expires.strftime('%Y-%m-%d %H:%M')
            msg = f'You are banned until {expires_str}. Reason: {reason or "Violation"}'
        else:
            msg = f'You are permanently banned. Reason: {reason or "Violation"}'
        return jsonify({"error": msg, "banned": True}), 403
    
    try:
        data = request.get_json()
        text = data.get('text', '').strip()
        
        if not text:
            return jsonify({"error": "Empty message"}), 400
        
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        
        if db_type == 'postgres':
            c.execute("""
                INSERT INTO community_messages (user_id, text, timestamp, google_name, google_picture) 
                VALUES (%s, %s, %s, %s, %s)
            """, (session['user_id'], text, datetime.now().isoformat(), 
                   session.get('user_name'), session.get('user_picture')))
        else:
            c.execute("""
                INSERT INTO community_messages (user_id, text, timestamp, google_name, google_picture) 
                VALUES (?, ?, ?, ?, ?)
            """, (session['user_id'], text, datetime.now().isoformat(), 
                   session.get('user_name'), session.get('user_picture')))
        
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/delete_community/<int:message_id>', methods=['DELETE'])
def delete_community_message(message_id):
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    if not session.get('is_admin'):
        return jsonify({"error": "Admin required"}), 403
    
    try:
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        
        if db_type == 'postgres':
            c.execute("DELETE FROM community_messages WHERE id = %s", (message_id,))
        else:
            c.execute("DELETE FROM community_messages WHERE id = ?", (message_id,))
        
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/check_like/<int:verse_id>')
def check_like(verse_id):
    if 'user_id' not in session:
        return jsonify({"liked": False})
    
    try:
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        
        if db_type == 'postgres':
            c.execute("SELECT id FROM likes WHERE user_id = %s AND verse_id = %s", (session['user_id'], verse_id))
        else:
            c.execute("SELECT id FROM likes WHERE user_id = ? AND verse_id = ?", (session['user_id'], verse_id))
        
        liked = c.fetchone() is not None
        conn.close()
        return jsonify({"liked": liked})
    except Exception as e:
        return jsonify({"liked": False})

@app.route('/api/check_save/<int:verse_id>')
def check_save(verse_id):
    if 'user_id' not in session:
        return jsonify({"saved": False})
    
    try:
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        
        if db_type == 'postgres':
            c.execute("SELECT id FROM saves WHERE user_id = %s AND verse_id = %s", (session['user_id'], verse_id))
        else:
            c.execute("SELECT id FROM saves WHERE user_id = ? AND verse_id = ?", (session['user_id'], verse_id))
        
        saved = c.fetchone() is not None
        conn.close()
        return jsonify({"saved": saved})
    except Exception as e:
        return jsonify({"saved": False})

@app.route('/api/ban_status')
def ban_status():
    """Get current user's ban status"""
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    is_banned, reason, expires = check_ban_status(session['user_id'])
    
    status = {
        "is_banned": is_banned,
        "reason": reason,
        "expires": expires
    }
    
    if expires and is_banned:
        try:
            if isinstance(expires, str):
                expires_dt = datetime.fromisoformat(expires.replace('Z', '+00:00').replace('+00:00', ''))
            else:
                expires_dt = expires
            
            now = datetime.now()
            if expires_dt > now:
                diff = expires_dt - now
                hours, remainder = divmod(diff.seconds, 3600)
                minutes, _ = divmod(remainder, 60)
                days = diff.days
                
                if days > 0:
                    status["time_remaining"] = f"{days}d {hours}h {minutes}m"
                else:
                    status["time_remaining"] = f"{hours}h {minutes}m"
            else:
                status["time_remaining"] = "Expired"
        except:
            status["time_remaining"] = "Unknown"
    
    return jsonify(status)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
