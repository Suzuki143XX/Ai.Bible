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
import logging
from datetime import datetime, timedelta
from functools import wraps

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.permanent_session_lifetime = timedelta(days=30)

@app.before_request
def make_session_permanent():
    session.permanent = True

# Configuration
app.secret_key = os.environ.get('SECRET_KEY', 'eK8#mP2$vL9@nQ4&wX5*fJ7!hR3(tY6)bU1$cI0~pO8+lA2=zS9')
PUBLIC_URL = os.environ.get('RENDER_EXTERNAL_URL', 'https://aibible.onrender.com')

GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '420462376171-neu8kbc7cm1geu2ov70gd10fh9e2210i.apps.googleusercontent.com')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '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')
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

ADMIN_CODE = os.environ.get('ADMIN_CODE', 'God Is All')
MASTER_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'God Is All')

DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///bible_ios.db')
if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

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
            logger.warning("psycopg2 not installed, falling back to SQLite")
            conn = sqlite3.connect('bible_ios.db', timeout=20)
            conn.row_factory = sqlite3.Row
            return conn, 'sqlite'
        except Exception as e:
            logger.error(f"PostgreSQL connection failed: {e}")
            # Fallback to SQLite if Postgres fails
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
        logger.info(f"Database initialized ({db_type})")
    except Exception as e:
        logger.error(f"DB Init Error: {e}")
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
        logger.error(f"Log error: {e}")

def check_ban_status(user_id):
    """Check if user is currently banned. Returns (is_banned, reason, expires_at)"""
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
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
    except Exception as e:
        logger.error(f"Ban check error: {e}")
        conn.close()
        return (False, None, None)

class BibleGenerator:
    def __init__(self):
        self.running = True
        self.interval = 60
        self.time_left = 60
        self.current_verse = None
        self.total_verses = 0
        self.session_id = secrets.token_hex(8)
        self.thread = None
        self.lock = threading.Lock()
        
        # Fallback verses in case API fails
        self.fallback_verses = [
            {"id": 1, "ref": "John 3:16", "text": "For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life.", "trans": "KJV", "source": "Fallback", "book": "John"},
            {"id": 2, "ref": "Philippians 4:13", "text": "I can do all things through Christ which strengtheneth me.", "trans": "KJV", "source": "Fallback", "book": "Philippians"},
            {"id": 3, "ref": "Psalm 23:1", "text": "The LORD is my shepherd; I shall not want.", "trans": "KJV", "source": "Fallback", "book": "Psalm"},
            {"id": 4, "ref": "Romans 8:28", "text": "And we know that all things work together for good to them that love God, to them who are the called according to his purpose.", "trans": "KJV", "source": "Fallback", "book": "Romans"},
            {"id": 5, "ref": "Jeremiah 29:11", "text": "For I know the thoughts that I think toward you, saith the LORD, thoughts of peace, and not of evil, to give you an expected end.", "trans": "KJV", "source": "Fallback", "book": "Jeremiah"}
        ]
        
        # Start with a fallback verse immediately
        self.current_verse = random.choice(self.fallback_verses)
        self.current_verse['session_id'] = self.session_id
        
        self.networks = [
            {"name": "Bible-API.com", "url": "https://bible-api.com/?random=verse"},
            {"name": "labs.bible.org", "url": "https://labs.bible.org/api/?passage=random&type=json"},
            {"name": "KJV Random", "url": "https://bible-api.com/?random=verse&translation=kjv"}
        ]
        self.network_idx = 0
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        
        # Start thread
        self.start_thread()
    
    def start_thread(self):
        """Start or restart the generator thread"""
        if self.thread is None or not self.thread.is_alive():
            self.thread = threading.Thread(target=self.loop)
            self.thread.daemon = True
            self.thread.start()
            logger.info("BibleGenerator thread started")
    
    def set_interval(self, seconds):
        with self.lock:
            self.interval = max(30, min(300, int(seconds)))
            self.time_left = min(self.time_left, self.interval)
    
    def extract_book(self, ref):
        match = re.match(r'^([0-9]?\s?[A-Za-z]+)', ref)
        return match.group(1) if match else "Unknown"
    
    def fetch_verse(self):
        """Fetch a new verse from API or use fallback"""
        network = self.networks[self.network_idx]
        verse_data = None
        
        try:
            r = self.session.get(network["url"], timeout=10)
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
                
                if text and ref:
                    book = self.extract_book(ref)
                    verse_data = {
                        "ref": ref,
                        "text": text,
                        "trans": trans,
                        "source": network["name"],
                        "book": book
                    }
        except Exception as e:
            logger.error(f"Fetch error from {network['name']}: {e}")
        
        # Rotate network for next time
        self.network_idx = (self.network_idx + 1) % len(self.networks)
        
        # If API failed, use fallback
        if not verse_data:
            logger.warning("Using fallback verse")
            fallback = random.choice(self.fallback_verses)
            verse_data = {
                "ref": fallback['ref'],
                "text": fallback['text'],
                "trans": fallback['trans'],
                "source": "Fallback",
                "book": fallback['book']
            }
        
        # Store in database
        try:
            conn, db_type = get_db()
            c = get_cursor(conn, db_type)
            
            if db_type == 'postgres':
                c.execute("""
                    INSERT INTO verses (reference, text, translation, source, timestamp, book) 
                    VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING
                """, (verse_data['ref'], verse_data['text'], verse_data['trans'], 
                      verse_data['source'], datetime.now().isoformat(), verse_data['book']))
            else:
                c.execute("INSERT OR IGNORE INTO verses (reference, text, translation, source, timestamp, book) VALUES (?, ?, ?, ?, ?, ?)",
                          (verse_data['ref'], verse_data['text'], verse_data['trans'], 
                           verse_data['source'], datetime.now().isoformat(), verse_data['book']))
            
            conn.commit()
            
            # Get the ID
            if db_type == 'postgres':
                c.execute("SELECT id FROM verses WHERE reference = %s AND text = %s", 
                         (verse_data['ref'], verse_data['text']))
            else:
                c.execute("SELECT id FROM verses WHERE reference = ? AND text = ?", 
                         (verse_data['ref'], verse_data['text']))
            
            result = c.fetchone()
            verse_id = result['id'] if result else random.randint(1000, 9999)
            
            # Update session
            self.session_id = secrets.token_hex(8)
            
            conn.close()
            
            with self.lock:
                self.current_verse = {
                    "id": verse_id,
                    "ref": verse_data['ref'],
                    "text": verse_data['text'],
                    "trans": verse_data['trans'],
                    "source": verse_data['source'],
                    "book": verse_data['book'],
                    "is_new": True,
                    "session_id": self.session_id
                }
                self.total_verses += 1
                
            logger.info(f"New verse fetched: {verse_data['ref']}")
            return True
            
        except Exception as e:
            logger.error(f"Database error in fetch_verse: {e}")
            # Still update current_verse even if DB fails
            with self.lock:
                self.current_verse = {
                    "id": random.randint(1000, 9999),
                    "ref": verse_data['ref'],
                    "text": verse_data['text'],
                    "trans": verse_data['trans'],
                    "source": verse_data['source'],
                    "book": verse_data['book'],
                    "is_new": True,
                    "session_id": secrets.token_hex(8)
                }
            return True
    
    def get_current_verse(self):
        """Thread-safe get current verse"""
        with self.lock:
            return self.current_verse.copy() if self.current_verse else None
    
    def get_time_left(self):
        """Thread-safe get time left"""
        with self.lock:
            return self.time_left
    
    def reset_timer(self):
        """Reset the timer after fetching"""
        with self.lock:
            self.time_left = self.interval
    
    def decrement_timer(self):
        """Decrement timer by 1 second"""
        with self.lock:
            self.time_left -= 1
            return self.time_left
    
    def loop(self):
        """Main loop - runs forever"""
        while self.running:
            try:
                current = self.get_time_left()
                if current <= 0:
                    self.fetch_verse()
                    self.reset_timer()
                else:
                    self.decrement_timer()
            except Exception as e:
                logger.error(f"Critical error in generator loop: {e}")
                time.sleep(5)  # Wait before retrying
                continue
            time.sleep(1)

# Global generator instance
generator = BibleGenerator()

@app.before_request
def check_user_banned():
    """Check if current user is banned before processing request"""
    if 'user_id' in session:
        if request.endpoint in ['logout', 'check_ban', 'static', 'login', 'google_login', 'callback', 'health']:
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

@app.route('/health')
def health_check():
    """Health check endpoint to verify generator is running"""
    try:
        status = {
            "status": "healthy",
            "generator_running": generator.thread.is_alive() if generator.thread else False,
            "current_verse": generator.get_current_verse()['ref'] if generator.get_current_verse() else None,
            "time_left": generator.get_time_left(),
            "interval": generator.interval
        }
        return jsonify(status)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

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
    
    # Ensure generator thread is running
    generator.start_thread()
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
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
    except Exception as e:
        logger.error(f"Index error: {e}")
        return f"Error loading page: {e}", 500
    finally:
        conn.close()

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
        logger.error(f"Google login error: {e}")
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
        logger.error(f"Callback error: {e}")
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
    
    # Ensure thread is running
    generator.start_thread()
    
    return jsonify({
        "verse": generator.get_current_verse(),
        "countdown": generator.get_time_left(),
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
    
    try:
        if db_type == 'postgres':
            c.execute("SELECT created_at, is_admin, is_banned, role FROM users WHERE id = %s", (session['user_id'],))
        else:
            c.execute("SELECT created_at, is_admin, is_banned, role FROM users WHERE id = ?", (session['user_id'],))
        
        row = c.fetchone()
        
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
    except Exception as e:
        logger.error(f"User info error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/verify_admin', methods=['POST'])
def verify_admin():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    data = request.get_json()
    code = data.get('code', '')
    
    if code == ADMIN_CODE:
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        
        try:
            if db_type == 'postgres':
                c.execute("UPDATE users SET is_admin = 1, role = 'host' WHERE id = %s", (session['user_id'],))
            else:
                c.execute("UPDATE users SET is_admin = 1, role = 'host' WHERE id = ?", (session['user_id'],))
            
            conn.commit()
            
            session['is_admin'] = True
            session['role'] = 'host'
            log_action(session['user_id'], 'admin_verified', details={'code_used': True})
            return jsonify({"success": True, "role": ">Admin<"})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)})
        finally:
            conn.close()
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
    
    try:
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
        
        return jsonify({"total_verses": total, "liked": liked, "saved": saved, "comments": comments})
    except Exception as e:
        logger.error(f"Stats error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

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
    
    try:
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
        
        if liked:
            rec = generator.generate_smart_recommendation(session['user_id'])
            return jsonify({"liked": liked, "recommendation": rec})
        
        return jsonify({"liked": liked})
    except Exception as e:
        logger.error(f"Like error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

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
    
    try:
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
        return jsonify({"saved": saved})
    except Exception as e:
        logger.error(f"Save error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

def generate_smart_recommendation(self, user_id):
    """Generate recommendation based on user likes"""
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
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
    except Exception as e:
        logger.error(f"Recommendation error: {e}")
        return None
    finally:
        conn.close()

# Bind the method to the class
BibleGenerator.generate_smart_recommendation = generate_smart_recommendation

@app.route('/api/library')
def get_library():
    if 'user_id' not in session:
        return jsonify({"liked": [], "saved": [], "collections": []})
    
    is_banned, _, _ = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "banned"}), 403
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
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
        
        return jsonify({"liked": liked, "saved": saved, "collections": []})
    except Exception as e:
        logger.error(f"Library error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/recommendations')
def get_recommendations():
    if 'user_id' not in session:
        return jsonify([])
    
    is_banned, _, _ = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "banned"}), 403
    
    rec = generator.generate_smart_recommendation(session['user_id'])
    if rec:
        return jsonify({"recommendations": [rec]})
    return jsonify({"recommendations": []})

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
    
    try:
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
    except Exception as e:
        logger.error(f"Get comments error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

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
    
    try:
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
        return jsonify({"success": True, "id": comment_id})
    except Exception as e:
        logger.error(f"Post comment error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/community')
def get_community_messages():
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
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
    except Exception as e:
        logger.error(f"Get community error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

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
    
    try:
        if db_type == 'postgres':
            c.execute("INSERT INTO community_messages (user_id, text, timestamp, google_name, google_picture) VALUES (%s, %s, %s, %s, %s)",
                      (session['user_id'], text, datetime.now().isoformat(), 
                       session.get('user_name'), session.get('user_picture')))
        else:
            c.execute("INSERT INTO community_messages (user_id, text, timestamp, google_name, google_picture) VALUES (?, ?, ?, ?, ?)",
                      (session['user_id'], text, datetime.now().isoformat(), 
                       session.get('user_name'), session.get('user_picture')))
        
        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Post community error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/check_like/<int:verse_id>')
def check_like(verse_id):
    if 'user_id' not in session:
        return jsonify({"liked": False})
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        if db_type == 'postgres':
            c.execute("SELECT id FROM likes WHERE user_id = %s AND verse_id = %s", (session['user_id'], verse_id))
        else:
            c.execute("SELECT id FROM likes WHERE user_id = ? AND verse_id = ?", (session['user_id'], verse_id))
        
        liked = c.fetchone() is not None
        return jsonify({"liked": liked})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/check_save/<int:verse_id>')
def check_save(verse_id):
    if 'user_id' not in session:
        return jsonify({"saved": False})
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        if db_type == 'postgres':
            c.execute("SELECT id FROM saves WHERE user_id = %s AND verse_id = %s", (session['user_id'], verse_id))
        else:
            c.execute("SELECT id FROM saves WHERE user_id = ? AND verse_id = ?", (session['user_id'], verse_id))
        
        saved = c.fetchone() is not None
        return jsonify({"saved": saved})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
