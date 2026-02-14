from flask import Flask, render_template, jsonify, request, redirect, url_for, session, send_from_directory, flash, render_template_string
import sqlite3
import time
import threading
import requests
import os
import re
import secrets
import json
import random
from datetime import datetime, timedelta
from functools import wraps

# Use environment variables for configuration
app = Flask(__name__)
app.permanent_session_lifetime = timedelta(days=30)

@app.before_request
def make_session_permanent():
    session.permanent = True

# Configuration - Using environment variables with fallbacks from your keys
app.secret_key = os.environ.get('SECRET_KEY', 'eK8#mP2$vL9@nQ4&wX5*fJ7!hR3(tY6)bU1$cI0~pO8+lA2=zS9')

# IMPORTANT: Set this to your Render.com URL
PUBLIC_URL = os.environ.get('RENDER_EXTERNAL_URL', 'https://aibible.onrender.com')

# Google OAuth - Using your new credentials from ALL KEYS.txt
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '420462376171-neu8kbc7cm1geu2ov70gd10fh9e2210i.apps.googleusercontent.com')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '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')
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

ADMIN_CODE = os.environ.get('ADMIN_CODE', 'God Is All')
MASTER_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'God Is All')

# Database - Use Render PostgreSQL in production, SQLite locally
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///bible_ios.db')
if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

# Determine if we're using PostgreSQL (Render) or SQLite (local)
IS_POSTGRES = DATABASE_URL and ('postgresql' in DATABASE_URL or 'postgres' in DATABASE_URL)

def get_db():
    """Get database connection - PostgreSQL for Render, SQLite for local"""
    if IS_POSTGRES:
        try:
            import psycopg2
            import psycopg2.extras
            conn = psycopg2.connect(DATABASE_URL, sslmode='require')
            return conn, 'postgres'
        except ImportError:
            print("WARNING: psycopg2 not installed, falling back to SQLite")
            conn = sqlite3.connect('bible_ios.db', timeout=20)
            conn.row_factory = sqlite3.Row
            return conn, 'sqlite'
    else:
        conn = sqlite3.connect('bible_ios.db', timeout=20)
        conn.row_factory = sqlite3.Row
        return conn, 'sqlite'

def get_cursor(conn, db_type):
    """Get cursor with dict access"""
    if db_type == 'postgres':
        import psycopg2.extras
        return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    else:
        return conn.cursor()

def init_db():
    """Initialize database tables"""
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        if db_type == 'postgres':
            # PostgreSQL tables
            c.execute('''
                CREATE TABLE IF NOT EXISTS verses (
                    id SERIAL PRIMARY KEY, reference TEXT, text TEXT, 
                    translation TEXT, source TEXT, timestamp TEXT, book TEXT
                )
            ''')
            
            c.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY, google_id TEXT UNIQUE, email TEXT, 
                    name TEXT, picture TEXT, created_at TEXT, is_admin INTEGER DEFAULT 0,
                    is_banned BOOLEAN DEFAULT FALSE, ban_expires_at TIMESTAMP, ban_reason TEXT, role TEXT DEFAULT 'user'
                )
            ''')
            
            c.execute('''
                CREATE TABLE IF NOT EXISTS likes (
                    id SERIAL PRIMARY KEY, user_id INTEGER, verse_id INTEGER, 
                    timestamp TEXT, UNIQUE(user_id, verse_id)
                )
            ''')
            
            c.execute('''
                CREATE TABLE IF NOT EXISTS saves (
                    id SERIAL PRIMARY KEY, user_id INTEGER, verse_id INTEGER, 
                    timestamp TEXT, UNIQUE(user_id, verse_id)
                )
            ''')
            
            c.execute('''
                CREATE TABLE IF NOT EXISTS comments (
                    id SERIAL PRIMARY KEY, user_id INTEGER, verse_id INTEGER,
                    text TEXT, timestamp TEXT, google_name TEXT, google_picture TEXT
                )
            ''')
            
            c.execute('''
                CREATE TABLE IF NOT EXISTS collections (
                    id SERIAL PRIMARY KEY, user_id INTEGER, name TEXT, 
                    color TEXT, created_at TEXT
                )
            ''')
            
            c.execute('''
                CREATE TABLE IF NOT EXISTS verse_collections (
                    id SERIAL PRIMARY KEY, collection_id INTEGER, verse_id INTEGER,
                    UNIQUE(collection_id, verse_id)
                )
            ''')
            
            c.execute('''
                CREATE TABLE IF NOT EXISTS community_messages (
                    id SERIAL PRIMARY KEY, user_id INTEGER, text TEXT, 
                    timestamp TEXT, google_name TEXT, google_picture TEXT
                )
            ''')
            
            c.execute('''
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id SERIAL PRIMARY KEY, admin_id INTEGER,
                    action TEXT, target_user_id INTEGER, details TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
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
            
            c.execute('''CREATE TABLE IF NOT EXISTS community_messages 
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, text TEXT, 
                          timestamp TEXT, google_name TEXT, google_picture TEXT)''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS audit_logs 
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, admin_id INTEGER,
                          action TEXT, target_user_id INTEGER, details TEXT,
                          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        conn.commit()
        print(f"Database initialized ({db_type})")
    except Exception as e:
        print(f"DB Init Error: {e}")
    finally:
        conn.close()

init_db()

def log_action(admin_id, action, target_user_id=None, details=None):
    """Log admin actions for audit trail"""
    try:
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        
        if db_type == 'postgres':
            c.execute("INSERT INTO audit_logs (admin_id, action, target_user_id, details) VALUES (%s, %s, %s, %s)",
                      (admin_id, action, target_user_id, json.dumps(details) if details else None))
        else:
            c.execute("INSERT INTO audit_logs (admin_id, action, target_user_id, details) VALUES (?, ?, ?, ?)",
                      (admin_id, action, target_user_id, json.dumps(details) if details else None))
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Log error: {e}")

def check_ban_status(user_id):
    """Check if user is currently banned. Returns (is_banned, reason, expires_at)"""
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    if db_type == 'postgres':
        c.execute("SELECT is_banned, ban_expires_at, ban_reason FROM users WHERE id = %s", (user_id,))
    else:
        c.execute("SELECT is_banned, ban_expires_at, ban_reason FROM users WHERE id = ?", (user_id,))
    
    row = c.fetchone()
    conn.close()
    
    if not row:
        return (False, None, None)
    
    is_banned = bool(row['is_banned']) if isinstance(row, dict) else bool(row[0])
    expires_at = row['ban_expires_at'] if isinstance(row, dict) else row[1]
    reason = row['ban_reason'] if isinstance(row, dict) else row[2]
    
    # Check if temporary ban expired
    if is_banned and expires_at:
        try:
            expire_dt = datetime.fromisoformat(str(expires_at))
            if datetime.now() > expire_dt:
                # Auto-unban
                conn, db_type = get_db()
                c = get_cursor(conn, db_type)
                if db_type == 'postgres':
                    c.execute("UPDATE users SET is_banned = FALSE, ban_expires_at = NULL, ban_reason = NULL WHERE id = %s", (user_id,))
                else:
                    c.execute("UPDATE users SET is_banned = 0, ban_expires_at = NULL, ban_reason = NULL WHERE id = ?", (user_id,))
                conn.commit()
                conn.close()
                return (False, None, None)
        except:
            pass
    
    return (is_banned, reason, expires_at)

class BibleGenerator:
    def __init__(self):
        self.running = True
        self.interval = 60
        self.time_left = 60
        self.current_verse = None
        self.total_verses = 0
        self.session_id = secrets.token_hex(8)
        self.thread = threading.Thread(target=self.loop)
        self.thread.daemon = True
        self.thread.start()
        
        self.networks = [
            {"name": "Bible-API.com", "url": "https://bible-api.com/?random=verse"},
            {"name": "labs.bible.org", "url": "https://labs.bible.org/api/?passage=random&type=json"},
            {"name": "KJV Random", "url": "https://bible-api.com/?random=verse&translation=kjv"}
        ]
        self.network_idx = 0
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        self.fetch_verse()
    
    def set_interval(self, seconds):
        self.interval = max(30, min(300, int(seconds)))
        self.time_left = min(self.time_left, self.interval)
    
    def extract_book(self, ref):
        match = re.match(r'^([0-9]?\s?[A-Za-z]+)', ref)
        return match.group(1) if match else "Unknown"
    
    def fetch_verse(self):
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
                else:
                    c.execute("INSERT OR IGNORE INTO verses (reference, text, translation, source, timestamp, book) VALUES (?, ?, ?, ?, ?, ?)",
                              (ref, text, trans, network["name"], datetime.now().isoformat(), book))
                
                conn.commit()
                
                if db_type == 'postgres':
                    c.execute("SELECT id FROM verses WHERE reference = %s AND text = %s", (ref, text))
                else:
                    c.execute("SELECT id FROM verses WHERE reference = ? AND text = ?", (ref, text))
                
                result = c.fetchone()
                verse_id = result['id'] if result else None
                
                self.session_id = secrets.token_hex(8)
                expires = datetime.fromtimestamp(time.time() + self.interval).isoformat()
                
                if db_type == 'postgres':
                    c.execute("INSERT INTO verse_sessions (verse_id, session_id, created_at, expires_at) VALUES (%s, %s, %s, %s)",
                              (verse_id, self.session_id, datetime.now().isoformat(), expires))
                else:
                    c.execute("INSERT INTO verse_sessions (verse_id, session_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                              (verse_id, self.session_id, datetime.now().isoformat(), expires))
                
                # Auto-create book collection
                if db_type == 'postgres':
                    c.execute("SELECT id FROM collections WHERE name = %s AND user_id = 0", (book,))
                    if not c.fetchone():
                        colors = ["#FF6B6B", "#4ECDC4", "#45B7D1", "#FFA07A", "#98D8C8", "#F7DC6F", "#BB8FCE"]
                        c.execute("INSERT INTO collections (user_id, name, color, created_at) VALUES (%s, %s, %s, %s)",
                                  (0, book, random.choice(colors), datetime.now().isoformat()))
                else:
                    c.execute("SELECT id FROM collections WHERE name = ? AND user_id = 0", (book,))
                    if not c.fetchone():
                        colors = ["#FF6B6B", "#4ECDC4", "#45B7D1", "#FFA07A", "#98D8C8", "#F7DC6F", "#BB8FCE"]
                        c.execute("INSERT INTO collections (user_id, name, color, created_at) VALUES (?, ?, ?, ?)",
                                  (0, book, random.choice(colors), datetime.now().isoformat()))
                
                conn.commit()
                conn.close()
                
                self.current_verse = {
                    "id": verse_id, "ref": ref, "text": text,
                    "trans": trans, "source": network["name"], "book": book,
                    "is_new": True, "session_id": self.session_id
                }
                self.total_verses += 1
                return True
        except Exception as e:
            print(f"Fetch error: {e}")
        
        self.network_idx = (self.network_idx + 1) % len(self.networks)
        return False
    
    def generate_smart_recommendation(self, user_id):
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        
        if db_type == 'postgres':
            c.execute("""
                SELECT DISTINCT v.book FROM verses v 
                JOIN likes l ON v.id = l.verse_id 
                WHERE l.user_id = %s
                UNION
                SELECT DISTINCT v.book FROM verses v 
                JOIN saves s ON v.id = s.verse_id 
                WHERE s.user_id = %s
            """, (user_id, user_id))
        else:
            c.execute("""
                SELECT DISTINCT v.book FROM verses v 
                JOIN likes l ON v.id = l.verse_id 
                WHERE l.user_id = ?
                UNION
                SELECT DISTINCT v.book FROM verses v 
                JOIN saves s ON v.id = s.verse_id 
                WHERE s.user_id = ?
            """, (user_id, user_id))
        
        preferred_books = [row['book'] if isinstance(row, dict) else row[0] for row in c.fetchall()]
        
        if preferred_books:
            if db_type == 'postgres':
                placeholders = ','.join(['%s'] * len(preferred_books))
                c.execute(f"""
                    SELECT v.* FROM verses v
                    WHERE v.book IN ({placeholders})
                    AND v.id NOT IN (SELECT verse_id FROM likes WHERE user_id = %s)
                    AND v.id NOT IN (SELECT verse_id FROM saves WHERE user_id = %s)
                    ORDER BY RANDOM()
                    LIMIT 1
                """, (*preferred_books, user_id, user_id))
            else:
                placeholders = ','.join('?' for _ in preferred_books)
                c.execute(f"""
                    SELECT v.* FROM verses v
                    WHERE v.book IN ({placeholders})
                    AND v.id NOT IN (SELECT verse_id FROM likes WHERE user_id = ?)
                    AND v.id NOT IN (SELECT verse_id FROM saves WHERE user_id = ?)
                    ORDER BY RANDOM()
                    LIMIT 1
                """, (*preferred_books, user_id, user_id))
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
            return {
                "id": row['id'] if isinstance(row, dict) else row[0], 
                "ref": row['reference'] if isinstance(row, dict) else row[1], 
                "text": row['text'] if isinstance(row, dict) else row[2],
                "trans": row['translation'] if isinstance(row, dict) else row[3], 
                "book": row['book'] if isinstance(row, dict) else row[6],
                "reason": f"Because you like {row['book'] if isinstance(row, dict) else row[6]}" if preferred_books else "Recommended for you"
            }
        return None
    
    def loop(self):
        while self.running:
            try:
                if self.time_left <= 0:
                    self.fetch_verse()
                    self.time_left = self.interval
                else:
                    self.time_left -= 1
            except Exception as e:
                print(f"Loop error: {e}")
            time.sleep(1)

generator = BibleGenerator()

@app.before_request
def check_user_banned():
    """Check if current user is banned before processing request"""
    if 'user_id' in session:
        if request.endpoint in ['logout', 'check_ban', 'static', 'login', 'google_login', 'callback']:
            return None
        
        is_banned, reason, _ = check_ban_status(session['user_id'])
        if is_banned:
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({"error": "banned", "reason": reason, "message": "Your account has been banned"}), 403
            else:
                return render_template_string("""
                <!DOCTYPE html>
                <html>
                <head><title>Account Banned</title>
                <style>
                    body { background: #0a0a0f; color: white; font-family: system-ui; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
                    .ban-container { text-align: center; padding: 40px; background: rgba(255,55,95,0.1); border: 1px solid #ff375f; border-radius: 20px; max-width: 400px; }
                    h1 { color: #ff375f; margin-bottom: 20px; }
                    .reason { background: rgba(0,0,0,0.3); padding: 15px; border-radius: 10px; margin: 20px 0; font-style: italic; }
                    a { color: #0A84FF; text-decoration: none; }
                </style></head>
                <body>
                    <div class="ban-container">
                        <h1>⛔ Account Banned</h1>
                        <p>Your account has been suspended.</p>
                        {% if reason %}
                        <div class="reason">Reason: {{ reason }}</div>
                        {% endif %}
                        <p><a href="/logout">Logout</a></p>
                    </div>
                </body>
                </html>
                """, reason=reason), 403

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
    
    is_banned, reason, _ = check_ban_status(session['user_id'])
    if is_banned:
        return redirect(url_for('logout'))
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    if db_type == 'postgres':
        c.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
    else:
        c.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
    
    user = c.fetchone()
    
    if db_type == 'postgres':
        c.execute("SELECT COUNT(*) as count FROM verses")
        total_verses = c.fetchone()['count']
        c.execute("SELECT COUNT(*) as count FROM likes WHERE user_id = %s", (session['user_id'],))
        liked_count = c.fetchone()['count']
        c.execute("SELECT COUNT(*) as count FROM saves WHERE user_id = %s", (session['user_id'],))
        saved_count = c.fetchone()['count']
    else:
        c.execute("SELECT COUNT(*) as count FROM verses")
        total_verses = c.fetchone()[0]
        c.execute("SELECT COUNT(*) as count FROM likes WHERE user_id = ?", (session['user_id'],))
        liked_count = c.fetchone()[0]
        c.execute("SELECT COUNT(*) as count FROM saves WHERE user_id = ?", (session['user_id'],))
        saved_count = c.fetchone()[0]
    
    conn.close()
    
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    user_dict = {
        "id": user['id'] if isinstance(user, dict) else user[0],
        "name": user['name'] if isinstance(user, dict) else user[3],
        "email": user['email'] if isinstance(user, dict) else user[2],
        "picture": user['picture'] if isinstance(user, dict) else user[4]
    }
    
    return render_template('web.html', 
                         user=user_dict,
                         stats={"total_verses": total_verses, "liked": liked_count, "saved": saved_count})

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/google-login')
def google_login():
    try:
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
        print(f"Google login error: {e}")
        return f"Error initiating Google login: {str(e)}", 500

@app.route('/callback')
def callback():
    code = request.args.get("code")
    error = request.args.get("error")
    state = request.args.get("state")
    
    if error:
        return f"OAuth Error: {error}. Please check that this URL ({PUBLIC_URL}) is authorized in Google Cloud Console.", 400
    if not code:
        return "No authorization code received", 400
    if state != session.get('oauth_state'):
        return "Invalid state parameter (CSRF protection)", 400
    
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
            error_data = token_response.json()
            error_desc = error_data.get('error_description', 'Unknown error')
            return f"Token exchange failed: {error_desc}. Make sure {callback_url} is in your Google Cloud Console authorized redirect URIs.", 400
        
        tokens = token_response.json()
        access_token = tokens.get("access_token")
        
        userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
        userinfo_response = requests.get(
            userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        if not userinfo_response.ok:
            return "Failed to get user info from Google", 400
        
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
                c.execute("INSERT INTO users (google_id, email, name, picture, created_at, is_admin, is_banned, role) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                          (google_id, email, name, picture, datetime.now().isoformat(), 0, False, 'user'))
            else:
                c.execute("INSERT INTO users (google_id, email, name, picture, created_at, is_admin, is_banned, role) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                          (google_id, email, name, picture, datetime.now().isoformat(), 0, 0, 'user'))
            conn.commit()
            
            if db_type == 'postgres':
                c.execute("SELECT * FROM users WHERE google_id = %s", (google_id,))
            else:
                c.execute("SELECT * FROM users WHERE google_id = ?", (google_id,))
            user = c.fetchone()
        
        conn.close()
        
        # Check if banned
        user_id = user['id'] if isinstance(user, dict) else user[0]
        is_banned, reason, _ = check_ban_status(user_id)
        if is_banned:
            return render_template_string("""
            <h1>Account Banned</h1>
            <p>Your account has been banned.</p>
            <p>Reason: {{ reason }}</p>
            <a href="/logout">Logout</a>
            """, reason=reason), 403
        
        session['user_id'] = user_id
        session['user_name'] = user['name'] if isinstance(user, dict) else user[3]
        session['user_picture'] = user['picture'] if isinstance(user, dict) else user[4]
        session['is_admin'] = bool(user['is_admin']) if isinstance(user, dict) else bool(user[6])
        session['role'] = user['role'] if isinstance(user, dict) else (user[10] if len(user) > 10 else 'user')
        
        return redirect(url_for('index'))
        
    except Exception as e:
        print(f"Callback error: {e}")
        import traceback
        traceback.print_exc()
        return f"Authentication error: {str(e)}. Please contact support.", 500

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/check_ban')
def check_ban():
    if 'user_id' not in session:
        return jsonify({"banned": False})
    
    is_banned, reason, expires_at = check_ban_status(session['user_id'])
    return jsonify({
        "banned": is_banned,
        "reason": reason,
        "expires_at": expires_at
    })

@app.route('/api/current')
def get_current():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    is_banned, _, _ = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "banned", "message": "Account banned"}), 403
    
    return jsonify({
        "verse": generator.current_verse,
        "countdown": generator.time_left,
        "total_verses": generator.total_verses,
        "session_id": generator.session_id,
        "interval": generator.interval
    })

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
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    if db_type == 'postgres':
        c.execute("SELECT created_at, is_admin, is_banned, role FROM users WHERE id = %s", (session['user_id'],))
    else:
        c.execute("SELECT created_at, is_admin, is_banned, role FROM users WHERE id = ?", (session['user_id'],))
    
    row = c.fetchone()
    conn.close()
    
    if row:
        if isinstance(row, dict):
            return jsonify({
                "created_at": row['created_at'],
                "is_admin": bool(row['is_admin']),
                "is_banned": bool(row['is_banned']),
                "role": row['role'] or 'user',
                "session_admin": session.get('is_admin', False)
            })
        else:
            return jsonify({
                "created_at": row[0],
                "is_admin": bool(row[1]),
                "is_banned": bool(row[2]),
                "role": row[3] if row[3] else 'user',
                "session_admin": session.get('is_admin', False)
            })
    return jsonify({"created_at": None, "is_admin": False, "is_banned": False, "role": "user"})

@app.route('/api/verify_admin', methods=['POST'])
def verify_admin():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    data = request.get_json()
    code = data.get('code', '')
    
    if code == ADMIN_CODE:
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        
        if db_type == 'postgres':
            c.execute("UPDATE users SET is_admin = 1, role = 'host' WHERE id = %s", (session['user_id'],))
        else:
            c.execute("UPDATE users SET is_admin = 1, role = 'host' WHERE id = ?", (session['user_id'],))
        
        conn.commit()
        conn.close()
        
        session['is_admin'] = True
        session['role'] = 'host'
        log_action(session['user_id'], 'admin_verified', details={'code_used': True})
        return jsonify({"success": True, "role": ">Admin<"})
    else:
        return jsonify({"success": False, "error": "Wrong code"})

@app.route('/api/stats')
def get_stats():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    is_banned, _, _ = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "banned"}), 403
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    if db_type == 'postgres':
        c.execute("SELECT COUNT(*) as count FROM verses")
        total = c.fetchone()['count']
        c.execute("SELECT COUNT(*) as count FROM likes WHERE user_id = %s", (session['user_id'],))
        liked = c.fetchone()['count']
        c.execute("SELECT COUNT(*) as count FROM saves WHERE user_id = %s", (session['user_id'],))
        saved = c.fetchone()['count']
        c.execute("SELECT COUNT(*) as count FROM comments WHERE user_id = %s", (session['user_id'],))
        comments = c.fetchone()['count']
    else:
        c.execute("SELECT COUNT(*) as count FROM verses")
        total = c.fetchone()[0]
        c.execute("SELECT COUNT(*) as count FROM likes WHERE user_id = ?", (session['user_id'],))
        liked = c.fetchone()[0]
        c.execute("SELECT COUNT(*) as count FROM saves WHERE user_id = ?", (session['user_id'],))
        saved = c.fetchone()[0]
        c.execute("SELECT COUNT(*) as count FROM comments WHERE user_id = ?", (session['user_id'],))
        comments = c.fetchone()[0]
    
    conn.close()
    return jsonify({"total_verses": total, "liked": liked, "saved": saved, "comments": comments})

@app.route('/api/like', methods=['POST'])
def like_verse():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    is_banned, _, _ = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "banned", "message": "Account banned"}), 403
    
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

@app.route('/api/save', methods=['POST'])
def save_verse():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    is_banned, _, _ = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "banned"}), 403
    
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

@app.route('/api/library')
def get_library():
    if 'user_id' not in session:
        return jsonify({"liked": [], "saved": [], "collections": []})
    
    is_banned, _, _ = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "banned"}), 403
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    if db_type == 'postgres':
        c.execute("""
            SELECT v.id, v.reference, v.text, v.translation, v.source, v.book, l.timestamp as liked_at
            FROM verses v 
            JOIN likes l ON v.id = l.verse_id 
            WHERE l.user_id = %s 
            ORDER BY l.timestamp DESC
        """, (session['user_id'],))
        liked = [{"id": row['id'], "ref": row['reference'], "text": row['text'], "trans": row['translation'], 
                  "source": row['source'], "book": row['book'], "liked_at": row['liked_at'], "saved_at": None} for row in c.fetchall()]
        
        c.execute("""
            SELECT v.id, v.reference, v.text, v.translation, v.source, v.book, s.timestamp as saved_at
            FROM verses v 
            JOIN saves s ON v.id = s.verse_id 
            WHERE s.user_id = %s 
            ORDER BY s.timestamp DESC
        """, (session['user_id'],))
        saved = [{"id": row['id'], "ref": row['reference'], "text": row['text'], "trans": row['translation'], 
                  "source": row['source'], "book": row['book'], "liked_at": None, "saved_at": row['saved_at']} for row in c.fetchall()]
        
        c.execute("""
            SELECT c.id, c.name, c.color, COUNT(vc.verse_id) as count 
            FROM collections c
            LEFT JOIN verse_collections vc ON c.id = vc.collection_id
            WHERE c.user_id = %s
            GROUP BY c.id
        """, (session['user_id'],))
    else:
        c.execute("""
            SELECT v.id, v.reference, v.text, v.translation, v.source, v.book, l.timestamp as liked_at
            FROM verses v 
            JOIN likes l ON v.id = l.verse_id 
            WHERE l.user_id = ? 
            ORDER BY l.timestamp DESC
        """, (session['user_id'],))
        liked = [{"id": row[0], "ref": row[1], "text": row[2], "trans": row[3], 
                  "source": row[4], "book": row[6], "liked_at": row[7], "saved_at": None} for row in c.fetchall()]
        
        c.execute("""
            SELECT v.id, v.reference, v.text, v.translation, v.source, v.book, s.timestamp as saved_at
            FROM verses v 
            JOIN saves s ON v.id = s.verse_id 
            WHERE s.user_id = ? 
            ORDER BY s.timestamp DESC
        """, (session['user_id'],))
        saved = [{"id": row[0], "ref": row[1], "text": row[2], "trans": row[3], 
                  "source": row[4], "book": row[6], "liked_at": None, "saved_at": row[7]} for row in c.fetchall()]
        
        c.execute("""
            SELECT c.id, c.name, c.color, COUNT(vc.verse_id) as count 
            FROM collections c
            LEFT JOIN verse_collections vc ON c.id = vc.collection_id
            WHERE c.user_id = ?
            GROUP BY c.id
        """, (session['user_id'],))
    
    collections = []
    for row in c.fetchall():
        if db_type == 'postgres':
            c.execute("""
                SELECT v.id, v.reference, v.text FROM verses v
                JOIN verse_collections vc ON v.id = vc.verse_id
                WHERE vc.collection_id = %s
            """, (row['id'],))
            verses = [{"id": v['id'], "ref": v['reference'], "text": v['text']} for v in c.fetchall()]
            collections.append({
                "id": row['id'], "name": row['name'], "color": row['color'], 
                "count": row['count'], "verses": verses
            })
        else:
            c.execute("""
                SELECT v.id, v.reference, v.text FROM verses v
                JOIN verse_collections vc ON v.id = vc.verse_id
                WHERE vc.collection_id = ?
            """, (row[0],))
            verses = [{"id": v[0], "ref": v[1], "text": v[2]} for v in c.fetchall()]
            collections.append({
                "id": row[0], "name": row[1], "color": row[2], 
                "count": row[3], "verses": verses
            })
    
    conn.close()
    return jsonify({"liked": liked, "saved": saved, "collections": collections})

@app.route('/api/collections/add', methods=['POST'])
def add_to_collection():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    is_banned, _, _ = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "banned"}), 403
    
    data = request.get_json()
    collection_id = data.get('collection_id')
    verse_id = data.get('verse_id')
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        if db_type == 'postgres':
            c.execute("INSERT INTO verse_collections (collection_id, verse_id) VALUES (%s, %s)",
                      (collection_id, verse_id))
        else:
            c.execute("INSERT INTO verse_collections (collection_id, verse_id) VALUES (?, ?)",
                      (collection_id, verse_id))
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        conn.close()
        return jsonify({"success": False, "error": "Already in collection"})

@app.route('/api/collections/create', methods=['POST'])
def create_collection():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    is_banned, _, _ = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "banned"}), 403
    
    data = request.get_json()
    name = data.get('name')
    color = data.get('color', '#0A84FF')
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    if db_type == 'postgres':
        c.execute("INSERT INTO collections (user_id, name, color, created_at) VALUES (%s, %s, %s, %s) RETURNING id",
                  (session['user_id'], name, color, datetime.now().isoformat()))
        new_id = c.fetchone()['id']
    else:
        c.execute("INSERT INTO collections (user_id, name, color, created_at) VALUES (?, ?, ?, ?)",
                  (session['user_id'], name, color, datetime.now().isoformat()))
        new_id = c.lastrowid
    
    conn.commit()
    conn.close()
    return jsonify({"id": new_id, "name": name, "color": color, "count": 0, "verses": []})

@app.route('/api/recommendations')
def get_recommendations():
    if 'user_id' not in session:
        return jsonify([])
    
    is_banned, _, _ = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "banned"}), 403
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    if db_type == 'postgres':
        c.execute("SELECT COUNT(*) FROM likes WHERE user_id = %s", (session['user_id'],))
        has_likes = c.fetchone()['count'] > 0
    else:
        c.execute("SELECT COUNT(*) FROM likes WHERE user_id = ?", (session['user_id'],))
        has_likes = c.fetchone()[0] > 0
    
    conn.close()
    
    rec = generator.generate_smart_recommendation(session['user_id'])
    if rec:
        return jsonify({"has_likes": has_likes, "recommendations": [rec]})
    return jsonify({"has_likes": has_likes, "recommendations": []})

@app.route('/api/generate-recommendation', methods=['POST'])
def generate_rec():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    is_banned, _, _ = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "banned"}), 403
    
    rec = generator.generate_smart_recommendation(session['user_id'])
    if rec:
        return jsonify({"success": True, "recommendation": rec})
    return jsonify({"success": False})

@app.route('/api/comments/<int:verse_id>')
def get_comments(verse_id):
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    if db_type == 'postgres':
        c.execute("""
            SELECT c.*, u.name, u.picture 
            FROM comments c
            JOIN users u ON c.user_id = u.id
            WHERE c.verse_id = %s
            ORDER BY c.timestamp DESC
        """, (verse_id,))
    else:
        c.execute("""
            SELECT c.*, u.name, u.picture 
            FROM comments c
            JOIN users u ON c.user_id = u.id
            WHERE c.verse_id = ?
            ORDER BY c.timestamp DESC
        """, (verse_id,))
    
    rows = c.fetchall()
    conn.close()
    
    comments = []
    for row in rows:
        if isinstance(row, dict):
            comments.append({
                "id": row['id'], "text": row['text'], "timestamp": row['timestamp'],
                "user_name": row['name'], "user_picture": row['picture'], "user_id": row['user_id']
            })
        else:
            comments.append({
                "id": row[0], "text": row[3], "timestamp": row[4],
                "user_name": row[7], "user_picture": row[8], "user_id": row[1]
            })
    
    return jsonify(comments)

@app.route('/api/comments', methods=['POST'])
def post_comment():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    is_banned, _, _ = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "banned", "message": "Account banned"}), 403
    
    data = request.get_json()
    verse_id = data.get('verse_id')
    text = data.get('text', '').strip()
    
    if not text:
        return jsonify({"error": "Empty comment"}), 400
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    if db_type == 'postgres':
        c.execute("INSERT INTO comments (user_id, verse_id, text, timestamp, google_name, google_picture) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
                  (session['user_id'], verse_id, text, datetime.now().isoformat(), 
                   session.get('user_name'), session.get('user_picture')))
        comment_id = c.fetchone()['id']
    else:
        c.execute("INSERT INTO comments (user_id, verse_id, text, timestamp, google_name, google_picture) VALUES (?, ?, ?, ?, ?, ?)",
                  (session['user_id'], verse_id, text, datetime.now().isoformat(), 
                   session.get('user_name'), session.get('user_picture')))
        comment_id = c.lastrowid
    
    conn.commit()
    
    if db_type == 'postgres':
        c.execute("SELECT c.*, u.name, u.picture FROM comments c JOIN users u ON c.user_id = u.id WHERE c.id = %s", (comment_id,))
    else:
        c.execute("SELECT c.*, u.name, u.picture FROM comments c JOIN users u ON c.user_id = u.id WHERE c.id = ?", (comment_id,))
    
    row = c.fetchone()
    conn.close()
    
    return jsonify({
        "id": row['id'] if isinstance(row, dict) else row[0],
        "text": row['text'] if isinstance(row, dict) else row[3],
        "timestamp": row['timestamp'] if isinstance(row, dict) else row[4],
        "user_name": row['name'] if isinstance(row, dict) else row[7],
        "user_picture": row['picture'] if isinstance(row, dict) else row[8],
        "user_id": row['user_id'] if isinstance(row, dict) else row[1]
    })

@app.route('/api/admin/delete_comment/<int:comment_id>', methods=['DELETE'])
def delete_comment(comment_id):
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    if not session.get('is_admin'):
        return jsonify({"error": "Admin required"}), 403
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    if db_type == 'postgres':
        c.execute("DELETE FROM comments WHERE id = %s", (comment_id,))
    else:
        c.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
    
    conn.commit()
    conn.close()
    
    log_action(session['user_id'], 'delete_comment', details={'comment_id': comment_id})
    return jsonify({"success": True})

@app.route('/api/community')
def get_community_messages():
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    if db_type == 'postgres':
        c.execute("""
            SELECT m.*, u.name, u.picture 
            FROM community_messages m
            JOIN users u ON m.user_id = u.id
            ORDER BY m.timestamp DESC
            LIMIT 100
        """)
    else:
        c.execute("""
            SELECT m.*, u.name, u.picture 
            FROM community_messages m
            JOIN users u ON m.user_id = u.id
            ORDER BY m.timestamp DESC
            LIMIT 100
        """)
    
    rows = c.fetchall()
    conn.close()
    
    messages = []
    for row in rows:
        if isinstance(row, dict):
            messages.append({
                "id": row['id'], "text": row['text'], "timestamp": row['timestamp'],
                "user_name": row['name'], "user_picture": row['picture'], "user_id": row['user_id']
            })
        else:
            messages.append({
                "id": row[0], "text": row[2], "timestamp": row[3],
                "user_name": row[5], "user_picture": row[6], "user_id": row[1]
            })
    
    return jsonify(messages)

@app.route('/api/community', methods=['POST'])
def post_community_message():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    is_banned, _, _ = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "banned", "message": "Account banned"}), 403
    
    data = request.get_json()
    text = data.get('text', '').strip()
    
    if not text:
        return jsonify({"error": "Empty message"}), 400
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    if db_type == 'postgres':
        c.execute("INSERT INTO community_messages (user_id, text, timestamp, google_name, google_picture) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                  (session['user_id'], text, datetime.now().isoformat(), 
                   session.get('user_name'), session.get('user_picture')))
        message_id = c.fetchone()['id']
    else:
        c.execute("INSERT INTO community_messages (user_id, text, timestamp, google_name, google_picture) VALUES (?, ?, ?, ?, ?)",
                  (session['user_id'], text, datetime.now().isoformat(), 
                   session.get('user_name'), session.get('user_picture')))
        message_id = c.lastrowid
    
    conn.commit()
    
    if db_type == 'postgres':
        c.execute("SELECT m.*, u.name, u.picture FROM community_messages m JOIN users u ON m.user_id = u.id WHERE m.id = %s", (message_id,))
    else:
        c.execute("SELECT m.*, u.name, u.picture FROM community_messages m JOIN users u ON m.user_id = u.id WHERE m.id = ?", (message_id,))
    
    row = c.fetchone()
    conn.close()
    
    return jsonify({
        "id": row['id'] if isinstance(row, dict) else row[0],
        "text": row['text'] if isinstance(row, dict) else row[2],
        "timestamp": row['timestamp'] if isinstance(row, dict) else row[3],
        "user_name": row['name'] if isinstance(row, dict) else row[5],
        "user_picture": row['picture'] if isinstance(row, dict) else row[6],
        "user_id": row['user_id'] if isinstance(row, dict) else row[1]
    })

@app.route('/api/admin/delete_community/<int:message_id>', methods=['DELETE'])
def delete_community_message(message_id):
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    if not session.get('is_admin'):
        return jsonify({"error": "Admin required"}), 403
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    if db_type == 'postgres':
        c.execute("DELETE FROM community_messages WHERE id = %s", (message_id,))
    else:
        c.execute("DELETE FROM community_messages WHERE id = ?", (message_id,))
    
    conn.commit()
    conn.close()
    
    log_action(session['user_id'], 'delete_community', details={'message_id': message_id})
    return jsonify({"success": True})

@app.route('/api/check_like/<int:verse_id>')
def check_like(verse_id):
    if 'user_id' not in session:
        return jsonify({"liked": False})
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    if db_type == 'postgres':
        c.execute("SELECT id FROM likes WHERE user_id = %s AND verse_id = %s", (session['user_id'], verse_id))
    else:
        c.execute("SELECT id FROM likes WHERE user_id = ? AND verse_id = ?", (session['user_id'], verse_id))
    
    liked = c.fetchone() is not None
    conn.close()
    return jsonify({"liked": liked})

@app.route('/api/check_save/<int:verse_id>')
def check_save(verse_id):
    if 'user_id' not in session:
        return jsonify({"saved": False})
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    if db_type == 'postgres':
        c.execute("SELECT id FROM saves WHERE user_id = %s AND verse_id = %s", (session['user_id'], verse_id))
    else:
        c.execute("SELECT id FROM saves WHERE user_id = ? AND verse_id = ?", (session['user_id'], verse_id))
    
    saved = c.fetchone() is not None
    conn.close()
    return jsonify({"saved": saved})

# Admin Ban Management API Routes

@app.route('/api/admin/ban_user', methods=['POST'])
def admin_ban_user():
    """Ban a user (admin only)"""
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    if not session.get('is_admin'):
        return jsonify({"error": "Admin required"}), 403
    
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'No data received'}), 400
    
    target_user_id = data.get('user_id')
    duration = data.get('duration')
    reason = data.get('reason', '').strip()
    
    if not target_user_id or not duration:
        return jsonify({'success': False, 'error': 'Missing user_id or duration'}), 400
    
    target_user_id = int(target_user_id)
    current_user_id = session.get('user_id')
    
    if target_user_id == current_user_id:
        return jsonify({'success': False, 'error': 'Cannot ban yourself'}), 403
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    # Check target user exists and get their role
    if db_type == 'postgres':
        c.execute("SELECT name, role, is_banned FROM users WHERE id = %s", (target_user_id,))
    else:
        c.execute("SELECT name, role, is_banned FROM users WHERE id = ?", (target_user_id,))
    
    target = c.fetchone()
    
    if not target:
        conn.close()
        return jsonify({'success': False, 'error': 'User not found'}), 404
    
    target_name = target['name'] if isinstance(target, dict) else target[0]
    target_role = (target['role'] if isinstance(target, dict) else target[1]) or 'user'
    is_already_banned = bool(target['is_banned'] if isinstance(target, dict) else target[2])
    
    if is_already_banned:
        conn.close()
        return jsonify({'success': False, 'error': 'User already banned'}), 400
    
    # Check role hierarchy
    current_role = session.get('role', 'user')
    role_hierarchy = {'user': 0, 'host': 1, 'mod': 2, 'contributor': 3, 'co_owner': 4, 'owner': 5}
    current_level = role_hierarchy.get(current_role, 0)
    target_level = role_hierarchy.get(target_role, 0)
    
    if target_level >= current_level and current_role != 'owner':
        conn.close()
        return jsonify({'success': False, 'error': 'Cannot ban users with equal or higher rank'}), 403
    
    # Calculate expiration
    expires_at = None
    if duration == '1hour':
        expires_at = (datetime.now() + timedelta(hours=1)).isoformat()
    elif duration == '1day':
        expires_at = (datetime.now() + timedelta(days=1)).isoformat()
    elif duration == '1week':
        expires_at = (datetime.now() + timedelta(weeks=1)).isoformat()
    elif duration == '1month':
        expires_at = (datetime.now() + timedelta(days=30)).isoformat()
    
    if db_type == 'postgres':
        c.execute("""
            UPDATE users SET is_banned = TRUE, ban_expires_at = %s, ban_reason = %s
            WHERE id = %s
        """, (expires_at, reason if reason else None, target_user_id))
    else:
        c.execute("""
            UPDATE users SET is_banned = 1, ban_expires_at = ?, ban_reason = ?
            WHERE id = ?
        """, (expires_at, reason, target_user_id))
    
    conn.commit()
    conn.close()
    
    log_action(current_user_id, 'ban', target_user_id, {
        'duration': duration, 
        'reason': reason,
        'expires_at': expires_at
    })
    
    return jsonify({
        'success': True,
        'message': f"User {target_name} has been banned",
        'expires_at': expires_at
    })

@app.route('/api/admin/unban_user/<int:user_id>', methods=['POST'])
def admin_unban_user(user_id):
    """Unban a user (admin only)"""
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    if not session.get('is_admin'):
        return jsonify({"error": "Admin required"}), 403
    
    current_user_id = session.get('user_id')
    
    if user_id == current_user_id:
        return jsonify({'success': False, 'error': 'Cannot unban yourself'}), 400
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    if db_type == 'postgres':
        c.execute("SELECT name, is_banned FROM users WHERE id = %s", (user_id,))
    else:
        c.execute("SELECT name, is_banned FROM users WHERE id = ?", (user_id,))
    
    user = c.fetchone()
    
    if not user:
        conn.close()
        return jsonify({'success': False, 'error': 'User not found'}), 404
    
    user_name = user['name'] if isinstance(user, dict) else user[0]
    is_banned = bool(user['is_banned'] if isinstance(user, dict) else user[1])
    
    if not is_banned:
        conn.close()
        return jsonify({'success': False, 'error': 'User is not banned'}), 400
    
    if db_type == 'postgres':
        c.execute("""
            UPDATE users SET is_banned = FALSE, ban_expires_at = NULL, ban_reason = NULL
            WHERE id = %s
        """, (user_id,))
    else:
        c.execute("""
            UPDATE users SET is_banned = 0, ban_expires_at = NULL, ban_reason = NULL
            WHERE id = ?
        """, (user_id,))
    
    conn.commit()
    conn.close()
    
    log_action(current_user_id, 'unban', user_id)
    
    return jsonify({
        'success': True,
        'message': f"User {user_name} has been unbanned"
    })

@app.route('/api/admin/user/<int:user_id>')
def admin_get_user(user_id):
    """Get detailed user info for admin panel"""
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    if not session.get('is_admin'):
        return jsonify({"error": "Admin required"}), 403
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    if db_type == 'postgres':
        c.execute("""
            SELECT id, name, email, picture, role, is_banned, ban_expires_at, ban_reason, created_at
            FROM users WHERE id = %s
        """, (user_id,))
    else:
        c.execute("""
            SELECT id, name, email, picture, role, is_banned, ban_expires_at, ban_reason, created_at
            FROM users WHERE id = ?
        """, (user_id,))
    
    user = c.fetchone()
    conn.close()
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    if isinstance(user, dict):
        return jsonify({
            "id": user['id'], "name": user['name'], "email": user['email'],
            "picture": user['picture'], "role": user['role'] or 'user',
            "is_banned": bool(user['is_banned']), "ban_expires_at": user['ban_expires_at'],
            "ban_reason": user['ban_reason'], "created_at": user['created_at']
        })
    else:
        return jsonify({
            "id": user[0], "name": user[1], "email": user[2],
            "picture": user[3], "role": user[4] or 'user',
            "is_banned": bool(user[5]), "ban_expires_at": user[6],
            "ban_reason": user[7], "created_at": user[8]
        })

@app.route('/api/admin/users')
def admin_list_users():
    """List users for admin panel"""
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    if not session.get('is_admin'):
        return jsonify({"error": "Admin required"}), 403
    
    search = request.args.get('search', '')
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    if search:
        if db_type == 'postgres':
            c.execute("""
                SELECT id, name, email, picture, role, is_banned, created_at
                FROM users 
                WHERE LOWER(name) LIKE %s OR LOWER(email) LIKE %s
                ORDER BY created_at DESC LIMIT 100
            """, (f'%{search.lower()}%', f'%{search.lower()}%'))
        else:
            c.execute("""
                SELECT id, name, email, picture, role, is_banned, created_at
                FROM users 
                WHERE LOWER(name) LIKE ? OR LOWER(email) LIKE ?
                ORDER BY created_at DESC LIMIT 100
            """, (f'%{search.lower()}%', f'%{search.lower()}%'))
    else:
        if db_type == 'postgres':
            c.execute("""
                SELECT id, name, email, picture, role, is_banned, created_at
                FROM users 
                ORDER BY created_at DESC LIMIT 100
            """)
        else:
            c.execute("""
                SELECT id, name, email, picture, role, is_banned, created_at
                FROM users 
                ORDER BY created_at DESC LIMIT 100
            """)
    
    rows = c.fetchall()
    conn.close()
    
    users = []
    for row in rows:
        if isinstance(row, dict):
            users.append({
                "id": row['id'], "name": row['name'], "email": row['email'],
                "picture": row['picture'], "role": row['role'] or 'user',
                "is_banned": bool(row['is_banned']), "created_at": row['created_at']
            })
        else:
            users.append({
                "id": row[0], "name": row[1], "email": row[2],
                "picture": row[3], "role": row[4] or 'user',
                "is_banned": bool(row[5]), "created_at": row[6]
            })
    
    return jsonify(users)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
