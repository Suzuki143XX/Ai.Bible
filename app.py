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

logging.basicConfig(level=logging.INFO)
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

def get_db():
    if DATABASE_URL and ('postgresql' in DATABASE_URL):
        import psycopg2
        conn = psycopg2.connect(DATABASE_URL, sslmode='require')
        return conn
    else:
        conn = sqlite3.connect(db_path, timeout=20)
        conn.row_factory = sqlite3.Row
        return conn

def get_cursor(conn):
    if DATABASE_URL and ('postgresql' in DATABASE_URL):
        import psycopg2.extras
        return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    else:
        return conn.cursor()

def init_db():
    try:
        conn = get_db()
        c = get_cursor(conn)
        
        if DATABASE_URL and ('postgresql' in DATABASE_URL):
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
            c.execute('''CREATE TABLE IF NOT EXISTS favorites 
                         (id SERIAL PRIMARY KEY, user_id INTEGER, verse_id INTEGER,
                          timestamp TEXT, UNIQUE(user_id, verse_id))''')
        else:
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
            c.execute('''CREATE TABLE IF NOT EXISTS favorites 
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, verse_id INTEGER,
                          timestamp TEXT, UNIQUE(user_id, verse_id))''')
        
        conn.commit()
        conn.close()
        logger.info("Database initialized")
    except Exception as e:
        logger.error(f"DB init error: {e}")
        raise

init_db()

def check_ban_status(user_id):
    """Check if user is banned. Returns (is_banned, reason, expires)"""
    try:
        conn = get_db()
        c = get_cursor(conn)
        
        if DATABASE_URL and ('postgresql' in DATABASE_URL):
            c.execute("SELECT is_banned, ban_expires_at, ban_reason FROM users WHERE id = %s", (user_id,))
        else:
            c.execute("SELECT is_banned, ban_expires_at, ban_reason FROM users WHERE id = ?", (user_id,))
            
        row = c.fetchone()
        conn.close()
        
        if not row:
            return False, None, None
        
        is_banned = row.get('is_banned', False) if isinstance(row, dict) else row[0]
        expires = row.get('ban_expires_at') if isinstance(row, dict) else row[1]
        reason = row.get('ban_reason') if isinstance(row, dict) else row[2]
        
        if isinstance(is_banned, str):
            is_banned = is_banned.lower() in ('true', 't', '1', 'yes')
        elif isinstance(is_banned, int):
            is_banned = bool(is_banned)
        
        if is_banned and expires:
            try:
                if isinstance(expires, str):
                    expires = expires.replace('Z', '+00:00')
                    if '+' in expires:
                        expires_dt = datetime.fromisoformat(expires)
                        expires_dt = expires_dt.replace(tzinfo=None)
                    else:
                        expires_dt = datetime.fromisoformat(expires)
                else:
                    expires_dt = expires
                
                if datetime.now() > expires_dt:
                    conn = get_db()
                    c = get_cursor(conn)
                    if DATABASE_URL and ('postgresql' in DATABASE_URL):
                        c.execute("UPDATE users SET is_banned = FALSE, ban_expires_at = NULL, ban_reason = NULL WHERE id = %s", (user_id,))
                    else:
                        c.execute("UPDATE users SET is_banned = 0, ban_expires_at = NULL, ban_reason = NULL WHERE id = ?", (user_id,))
                    conn.commit()
                    conn.close()
                    return False, None, None
            except Exception as e:
                logger.error(f"Ban expiry check error: {e}")
        
        return is_banned, reason, expires
        
    except Exception as e:
        logger.error(f"Ban check error: {e}")
        return False, None, None

@app.before_request
def global_ban_check():
    if 'user_id' not in session:
        return
    
    if request.endpoint in ['static', 'serve_audio', 'manifest', 'ban_status']:
        return
    
    if request.endpoint not in ['login', 'callback', 'google_login', 'logout']:
        is_banned, reason, expires = check_ban_status(session['user_id'])
        
        if is_banned:
            if expires:
                expires_str = str(expires)[:16] if len(str(expires)) > 16 else str(expires)
                msg = f'Banned until {expires_str}. Reason: {reason or "Violation"}'
            else:
                msg = f'Permanently banned. Reason: {reason or "Violation"}'
            
            if request.path.startswith('/api/') and request.method != 'GET':
                return jsonify({"error": msg, "banned": True}), 403
            
            if request.method == 'GET' and not request.path.startswith('/api/'):
                session.clear()
                flash(f'🚫 {msg}', 'error')
                return redirect(url_for('login'))

class BibleGenerator:
    def __init__(self):
        self.running = True
        self.interval = 300  # 5 minutes default
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
        self.interval = max(30, min(3600, int(seconds)))
    
    def get_time_left(self):
        return max(0, self.interval - int(time.time() - self.last_fetch))
    
    def check_and_update(self):
        if time.time() - self.last_fetch > self.interval:
            self.fetch_verse()
    
    def extract_book(self, ref):
        match = re.match(r'^([0-9]?\s?[A-Za-z]+)', ref)
        return match.group(1).strip() if match else "Unknown"
    
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
                
                conn = get_db()
                c = get_cursor(conn)
                
                # Check if verse exists
                if DATABASE_URL and ('postgresql' in DATABASE_URL):
                    c.execute("SELECT id FROM verses WHERE reference = %s AND text = %s", (ref, text))
                else:
                    c.execute("SELECT id FROM verses WHERE reference = ? AND text = ?", (ref, text))
                    
                existing = c.fetchone()
                
                if existing:
                    verse_id = existing['id'] if isinstance(existing, dict) else existing[0]
                else:
                    # Insert new verse
                    if DATABASE_URL and ('postgresql' in DATABASE_URL):
                        c.execute("""
                            INSERT INTO verses (reference, text, translation, source, timestamp, book) 
                            VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
                        """, (ref, text, trans, network["name"], datetime.now().isoformat(), book))
                        verse_id = c.fetchone()['id']
                    else:
                        c.execute("""
                            INSERT INTO verses (reference, text, translation, source, timestamp, book) 
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (ref, text, trans, network["name"], datetime.now().isoformat(), book))
                        verse_id = c.lastrowid
                
                conn.commit()
                self.session_id = secrets.token_hex(8)
                conn.close()
                
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
        """Fixed recommendation engine - properly queries liked/saved books"""
        try:
            conn = get_db()
            c = get_cursor(conn)
            is_postgres = DATABASE_URL and ('postgresql' in DATABASE_URL)
            
            # Get user's preferred books from likes
            if is_postgres:
                c.execute("""
                    SELECT DISTINCT v.book FROM verses v 
                    JOIN likes l ON v.id = l.verse_id 
                    WHERE l.user_id = %s
                """, (user_id,))
            else:
                c.execute("""
                    SELECT DISTINCT v.book FROM verses v 
                    JOIN likes l ON v.id = l.verse_id 
                    WHERE l.user_id = ?
                """, (user_id,))
            
            liked_books = [row['book'] if isinstance(row, dict) else row[0] for row in c.fetchall()]
            
            # Get user's preferred books from saves
            if is_postgres:
                c.execute("""
                    SELECT DISTINCT v.book FROM verses v 
                    JOIN saves s ON v.id = s.verse_id 
                    WHERE s.user_id = %s
                """, (user_id,))
            else:
                c.execute("""
                    SELECT DISTINCT v.book FROM verses v 
                    JOIN saves s ON v.id = s.verse_id 
                    WHERE s.user_id = ?
                """, (user_id,))
                
            saved_books = [row['book'] if isinstance(row, dict) else row[0] for row in c.fetchall()]
            
            # Combine unique books
            preferred_books = list(set(liked_books + saved_books))
            
            verse = None
            
            if preferred_books:
                # Try to find a verse from preferred books that user hasn't liked yet
                placeholders = ','.join(['%s'] * len(preferred_books)) if is_postgres else ','.join(['?'] * len(preferred_books))
                
                if is_postgres:
                    c.execute(f"""
                        SELECT * FROM verses
                        WHERE book IN ({placeholders})
                        AND id NOT IN (SELECT verse_id FROM likes WHERE user_id = %s)
                        ORDER BY RANDOM()
                        LIMIT 1
                    """, (*preferred_books, user_id))
                else:
                    c.execute(f"""
                        SELECT * FROM verses
                        WHERE book IN ({placeholders})
                        AND id NOT IN (SELECT verse_id FROM likes WHERE user_id = ?)
                        ORDER BY RANDOM()
                        LIMIT 1
                    """, (*preferred_books, user_id))
                
                verse = c.fetchone()
            
            # If no verse from preferred books, get any random verse not liked yet
            if not verse:
                if is_postgres:
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
                    
                verse = c.fetchone()
            
            # If still no verse (user liked everything), get any random verse
            if not verse:
                if is_postgres:
                    c.execute("SELECT * FROM verses ORDER BY RANDOM() LIMIT 1")
                else:
                    c.execute("SELECT * FROM verses ORDER BY RANDOM() LIMIT 1")
                verse = c.fetchone()
            
            conn.close()
            
            if verse:
                book = verse['book'] if isinstance(verse, dict) else verse[6]
                ref = verse['reference'] if isinstance(verse, dict) else verse[1]
                reason = f"Because you like {book}" if book in preferred_books else "Recommended for you"
                
                return {
                    "id": verse['id'] if isinstance(verse, dict) else verse[0], 
                    "ref": ref, 
                    "text": verse['text'] if isinstance(verse, dict) else verse[2],
                    "trans": verse['translation'] if isinstance(verse, dict) else verse[3], 
                    "book": book,
                    "reason": reason
                }
        except Exception as e:
            logger.error(f"Recommendation error: {e}")
            import traceback
            logger.error(traceback.format_exc())
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
    
    is_banned, reason, expires = check_ban_status(session['user_id'])
    if is_banned:
        session.clear()
        if expires:
            expires_str = str(expires)[:16]
            flash(f'🚫 Banned until {expires_str}. Reason: {reason or "Violation"}', 'error')
        else:
            flash(f'🚫 Permanently banned. Reason: {reason or "Violation"}', 'error')
        return redirect(url_for('login'))
    
    try:
        conn = get_db()
        c = get_cursor(conn)
        is_postgres = DATABASE_URL and ('postgresql' in DATABASE_URL)
        
        if is_postgres:
            c.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
        else:
            c.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
            
        user = c.fetchone()
        
        if not user:
            session.clear()
            conn.close()
            return redirect(url_for('login'))
        
        user_data = {
            'id': user['id'] if isinstance(user, dict) else user[0],
            'email': user['email'] if isinstance(user, dict) else user[2],
            'name': user['name'] if isinstance(user, dict) else user[3],
            'picture': user['picture'] if isinstance(user, dict) else user[4],
            'is_admin': bool(user.get('is_admin', 0)) if isinstance(user, dict) else bool(user[6]),
            'is_banned': bool(user.get('is_banned', False)) if isinstance(user, dict) else bool(user[7] if len(user) > 7 else 0),
        }
        
        if is_postgres:
            c.execute("SELECT COUNT(*) as count FROM verses")
            total_verses = c.fetchone()['count']
            
            c.execute("SELECT COUNT(*) as count FROM likes WHERE user_id = %s", (session['user_id'],))
            liked_count = c.fetchone()['count']
            
            c.execute("SELECT COUNT(*) as count FROM saves WHERE user_id = %s", (session['user_id'],))
            saved_count = c.fetchone()['count']
            
            c.execute("SELECT COUNT(*) as count FROM comments WHERE user_id = %s", (session['user_id'],))
            comment_count = c.fetchone()['count']
        else:
            c.execute("SELECT COUNT(*) as count FROM verses")
            total_verses = c.fetchone()[0]
            
            c.execute("SELECT COUNT(*) as count FROM likes WHERE user_id = ?", (session['user_id'],))
            liked_count = c.fetchone()[0]
            
            c.execute("SELECT COUNT(*) as count FROM saves WHERE user_id = ?", (session['user_id'],))
            saved_count = c.fetchone()[0]
            
            c.execute("SELECT COUNT(*) as count FROM comments WHERE user_id = ?", (session['user_id'],))
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
        return f"Error initiating login: {str(e)}", 500

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
        
        conn = get_db()
        c = get_cursor(conn)
        is_postgres = DATABASE_URL and ('postgresql' in DATABASE_URL)
        
        # Check if user exists
        if is_postgres:
            c.execute("SELECT * FROM users WHERE google_id = %s", (google_id,))
        else:
            c.execute("SELECT * FROM users WHERE google_id = ?", (google_id,))
            
        user = c.fetchone()
        
        if not user:
            # Insert new user
            if is_postgres:
                c.execute("""
                    INSERT INTO users (google_id, email, name, picture, created_at, is_admin) 
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT DO NOTHING
                """, (google_id, email, name, picture, datetime.now().isoformat(), 0))
            else:
                c.execute("""
                    INSERT OR IGNORE INTO users (google_id, email, name, picture, created_at, is_admin) 
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (google_id, email, name, picture, datetime.now().isoformat(), 0))
                
            conn.commit()
            
            if is_postgres:
                c.execute("SELECT * FROM users WHERE google_id = %s", (google_id,))
            else:
                c.execute("SELECT * FROM users WHERE google_id = ?", (google_id,))
                
            user = c.fetchone()
        
        user_id = user['id'] if isinstance(user, dict) else user[0]
        is_banned = bool(user.get('is_banned', False)) if isinstance(user, dict) else bool(user[7] if len(user) > 7 else 0)
        ban_expires = user.get('ban_expires_at') if isinstance(user, dict) else (user[8] if len(user) > 8 else None)
        ban_reason = user.get('ban_reason') if isinstance(user, dict) else (user[9] if len(user) > 9 else None)
        
        if is_banned:
            ban_active = True
            if ban_expires:
                try:
                    if isinstance(ban_expires, str):
                        expires_dt = datetime.fromisoformat(ban_expires.replace('Z', '+00:00').replace('+00:00', ''))
                    else:
                        expires_dt = ban_expires
                    
                    if datetime.now() > expires_dt:
                        if is_postgres:
                            c.execute("UPDATE users SET is_banned = FALSE, ban_expires_at = NULL, ban_reason = NULL WHERE id = %s", (user_id,))
                        else:
                            c.execute("UPDATE users SET is_banned = 0, ban_expires_at = NULL, ban_reason = NULL WHERE id = ?", (user_id,))
                        conn.commit()
                        ban_active = False
                except Exception as e:
                    logger.error(f"Ban check error in callback: {e}")
            
            if ban_active:
                conn.close()
                expires_str = str(ban_expires)[:16] if ban_expires else "Never"
                return f"""
                <html><body style="text-align:center;padding:50px; font-family: sans-serif; background: #1a1a2e; color: white;">
                    <h1>🚫 Banned</h1>
                    <p>Until: {expires_str}</p>
                    <p>Reason: {ban_reason or 'Violation'}</p>
                    <a href="/" style="color: #667eea;">Home</a>
                </body></html>
                """, 403
        
        conn.close()
        session['user_id'] = user_id
        session['user_name'] = name
        session['user_picture'] = picture
        session['is_admin'] = bool(user.get('is_admin', 0)) if isinstance(user, dict) else bool(user[6])
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
        logger.error(f"API current error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/set_interval', methods=['POST'])
def set_interval():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    # Only admins can change interval
    if not session.get('is_admin'):
        return jsonify({"error": "Admin required"}), 403
    
    data = request.get_json()
    interval = data.get('interval', 300)
    generator.set_interval(interval)
    return jsonify({"success": True, "interval": generator.interval})

@app.route('/api/user_info')
def get_user_info():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    try:
        conn = get_db()
        c = get_cursor(conn)
        is_postgres = DATABASE_URL and ('postgresql' in DATABASE_URL)
        
        if is_postgres:
            c.execute("SELECT created_at, is_admin FROM users WHERE id = %s", (session['user_id'],))
        else:
            c.execute("SELECT created_at, is_admin FROM users WHERE id = ?", (session['user_id'],))
            
        row = c.fetchone()
        conn.close()
        
        if row:
            return jsonify({
                "created_at": row['created_at'] if isinstance(row, dict) else row[0],
                "is_admin": bool(row.get('is_admin', 0)) if isinstance(row, dict) else bool(row[1]),
                "session_admin": session.get('is_admin', False)
            })
        return jsonify({"created_at": None, "is_admin": False, "session_admin": False})
    except Exception as e:
        logger.error(f"User info error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/recommendation')
def get_recommendation():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    try:
        rec = generator.generate_smart_recommendation(session['user_id'])
        if rec:
            return jsonify({"success": True, "verse": rec})
        else:
            return jsonify({"success": False, "message": "No recommendations available"})
    except Exception as e:
        logger.error(f"Recommendation API error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/verify_admin', methods=['POST'])
def verify_admin():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    data = request.get_json()
    code = data.get('code', '')
    
    if code == ADMIN_CODE:
        try:
            conn = get_db()
            c = get_cursor(conn)
            is_postgres = DATABASE_URL and ('postgresql' in DATABASE_URL)
            
            if is_postgres:
                c.execute("UPDATE users SET is_admin = 1 WHERE id = %s", (session['user_id'],))
            else:
                c.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (session['user_id'],))
                
            conn.commit()
            conn.close()
            
            session['is_admin'] = True
            return jsonify({"success": True, "role": "Admin"})
        except Exception as e:
            logger.error(f"Admin verify error: {e}")
            return jsonify({"success": False, "error": str(e)})
    else:
        return jsonify({"success": False, "error": "Wrong code"})

@app.route('/api/stats')
def get_stats():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    try:
        conn = get_db()
        c = get_cursor(conn)
        is_postgres = DATABASE_URL and ('postgresql' in DATABASE_URL)
        
        if is_postgres:
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
    except Exception as e:
        logger.error(f"Stats error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/like', methods=['POST'])
def like_verse():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    is_banned, reason, expires = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "You are banned", "banned": True}), 403
    
    try:
        data = request.get_json()
        verse_id = data.get('verse_id')
        
        conn = get_db()
        c = get_cursor(conn)
        is_postgres = DATABASE_URL and ('postgresql' in DATABASE_URL)
        
        if is_postgres:
            c.execute("SELECT id FROM likes WHERE user_id = %s AND verse_id = %s", (session['user_id'], verse_id))
        else:
            c.execute("SELECT id FROM likes WHERE user_id = ? AND verse_id = ?", (session['user_id'], verse_id))
            
        if c.fetchone():
            if is_postgres:
                c.execute("DELETE FROM likes WHERE user_id = %s AND verse_id = %s", (session['user_id'], verse_id))
            else:
                c.execute("DELETE FROM likes WHERE user_id = ? AND verse_id = ?", (session['user_id'], verse_id))
            liked = False
        else:
            if is_postgres:
                c.execute("INSERT INTO likes (user_id, verse_id, timestamp) VALUES (%s, %s, %s)",
                          (session['user_id'], verse_id, datetime.now().isoformat()))
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
        logger.error(f"Like error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/save', methods=['POST'])
def save_verse():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    is_banned, reason, expires = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "You are banned", "banned": True}), 403
    
    try:
        data = request.get_json()
        verse_id = data.get('verse_id')
        
        conn = get_db()
        c = get_cursor(conn)
        is_postgres = DATABASE_URL and ('postgresql' in DATABASE_URL)
        
        if is_postgres:
            c.execute("SELECT id FROM saves WHERE user_id = %s AND verse_id = %s", (session['user_id'], verse_id))
        else:
            c.execute("SELECT id FROM saves WHERE user_id = ? AND verse_id = ?", (session['user_id'], verse_id))
            
        if c.fetchone():
            if is_postgres:
                c.execute("DELETE FROM saves WHERE user_id = %s AND verse_id = %s", (session['user_id'], verse_id))
            else:
                c.execute("DELETE FROM saves WHERE user_id = ? AND verse_id = ?", (session['user_id'], verse_id))
            saved = False
        else:
            if is_postgres:
                c.execute("INSERT INTO saves (user_id, verse_id, timestamp) VALUES (%s, %s, %s)",
                          (session['user_id'], verse_id, datetime.now().isoformat()))
            else:
                c.execute("INSERT INTO saves (user_id, verse_id, timestamp) VALUES (?, ?, ?)",
                          (session['user_id'], verse_id, datetime.now().isoformat()))
            saved = True
        
        conn.commit()
        conn.close()
        return jsonify({"saved": saved})
    except Exception as e:
        logger.error(f"Save error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/favorite', methods=['POST'])
def favorite_verse():
    """Add verse to favorites (for drag and drop)"""
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    is_banned, reason, expires = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "You are banned", "banned": True}), 403
    
    try:
        data = request.get_json()
        verse_id = data.get('verse_id')
        
        conn = get_db()
        c = get_cursor(conn)
        is_postgres = DATABASE_URL and ('postgresql' in DATABASE_URL)
        
        # Check if already favorited
        if is_postgres:
            c.execute("SELECT id FROM favorites WHERE user_id = %s AND verse_id = %s", (session['user_id'], verse_id))
        else:
            c.execute("SELECT id FROM favorites WHERE user_id = ? AND verse_id = ?", (session['user_id'], verse_id))
            
        if not c.fetchone():
            if is_postgres:
                c.execute("INSERT INTO favorites (user_id, verse_id, timestamp) VALUES (%s, %s, %s)",
                          (session['user_id'], verse_id, datetime.now().isoformat()))
            else:
                c.execute("INSERT INTO favorites (user_id, verse_id, timestamp) VALUES (?, ?, ?)",
                          (session['user_id'], verse_id, datetime.now().isoformat()))
            conn.commit()
            conn.close()
            return jsonify({"success": True, "favorited": True})
        else:
            conn.close()
            return jsonify({"success": True, "favorited": False, "message": "Already in favorites"})
            
    except Exception as e:
        logger.error(f"Favorite error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/favorites')
def get_favorites():
    """Get user's favorited verses"""
    if 'user_id' not in session:
        return jsonify({"favorites": []})
    
    try:
        conn = get_db()
        c = get_cursor(conn)
        is_postgres = DATABASE_URL and ('postgresql' in DATABASE_URL)
        
        if is_postgres:
            c.execute("""
                SELECT v.id, v.reference, v.text, v.translation, v.source, v.book, f.timestamp
                FROM verses v 
                JOIN favorites f ON v.id = f.verse_id 
                WHERE f.user_id = %s 
                ORDER BY f.timestamp DESC
            """, (session['user_id'],))
        else:
            c.execute("""
                SELECT v.id, v.reference, v.text, v.translation, v.source, v.book, f.timestamp
                FROM verses v 
                JOIN favorites f ON v.id = f.verse_id 
                WHERE f.user_id = ? 
                ORDER BY f.timestamp DESC
            """, (session['user_id'],))
            
        rows = c.fetchall()
        conn.close()
        
        favorites = []
        for row in rows:
            if isinstance(row, dict):
                favorites.append({
                    'id': row['id'],
                    'ref': row['reference'],
                    'text': row['text'],
                    'trans': row['translation'],
                    'source': row['source'],
                    'book': row['book']
                })
            else:
                favorites.append({
                    'id': row[0],
                    'ref': row[1],
                    'text': row[2],
                    'trans': row[3],
                    'source': row[4],
                    'book': row[5]
                })
        
        return jsonify({"favorites": favorites})
    except Exception as e:
        logger.error(f"Get favorites error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/library')
def get_library():
    if 'user_id' not in session:
        return jsonify({"liked": [], "saved": [], "favorites": []})
    
    try:
        conn = get_db()
        c = get_cursor(conn)
        is_postgres = DATABASE_URL and ('postgresql' in DATABASE_URL)
        
        if is_postgres:
            c.execute("""
                SELECT v.id, v.reference, v.text, v.translation, v.source, v.book, l.timestamp as liked_at
                FROM verses v 
                JOIN likes l ON v.id = l.verse_id 
                WHERE l.user_id = %s 
                ORDER BY l.timestamp DESC
            """, (session['user_id'],))
        else:
            c.execute("""
                SELECT v.id, v.reference, v.text, v.translation, v.source, v.book, l.timestamp as liked_at
                FROM verses v 
                JOIN likes l ON v.id = l.verse_id 
                WHERE l.user_id = ? 
                ORDER BY l.timestamp DESC
            """, (session['user_id'],))
        liked_rows = c.fetchall()
        
        if is_postgres:
            c.execute("""
                SELECT v.id, v.reference, v.text, v.translation, v.source, v.book, s.timestamp as saved_at
                FROM verses v 
                JOIN saves s ON v.id = s.verse_id 
                WHERE s.user_id = %s 
                ORDER BY s.timestamp DESC
            """, (session['user_id'],))
        else:
            c.execute("""
                SELECT v.id, v.reference, v.text, v.translation, v.source, v.book, s.timestamp as saved_at
                FROM verses v 
                JOIN saves s ON v.id = s.verse_id 
                WHERE s.user_id = ? 
                ORDER BY s.timestamp DESC
            """, (session['user_id'],))
        saved_rows = c.fetchall()
        
        # Get favorites too
        if is_postgres:
            c.execute("""
                SELECT v.id, v.reference, v.text, v.translation, v.source, v.book
                FROM verses v 
                JOIN favorites f ON v.id = f.verse_id 
                WHERE f.user_id = %s 
                ORDER BY f.timestamp DESC
            """, (session['user_id'],))
        else:
            c.execute("""
                SELECT v.id, v.reference, v.text, v.translation, v.source, v.book
                FROM verses v 
                JOIN favorites f ON v.id = f.verse_id 
                WHERE f.user_id = ? 
                ORDER BY f.timestamp DESC
            """, (session['user_id'],))
        fav_rows = c.fetchall()
        
        liked = []
        for row in liked_rows:
            liked.append({
                'id': row['id'] if isinstance(row, dict) else row[0],
                'ref': row['reference'] if isinstance(row, dict) else row[1],
                'text': row['text'] if isinstance(row, dict) else row[2],
                'trans': row['translation'] if isinstance(row, dict) else row[3],
                'source': row['source'] if isinstance(row, dict) else row[4],
                'book': row['book'] if isinstance(row, dict) else row[5]
            })
        
        saved = []
        for row in saved_rows:
            saved.append({
                'id': row['id'] if isinstance(row, dict) else row[0],
                'ref': row['reference'] if isinstance(row, dict) else row[1],
                'text': row['text'] if isinstance(row, dict) else row[2],
                'trans': row['translation'] if isinstance(row, dict) else row[3],
                'source': row['source'] if isinstance(row, dict) else row[4],
                'book': row['book'] if isinstance(row, dict) else row[5]
            })
            
        favorites = []
        for row in fav_rows:
            favorites.append({
                'id': row['id'] if isinstance(row, dict) else row[0],
                'ref': row['reference'] if isinstance(row, dict) else row[1],
                'text': row['text'] if isinstance(row, dict) else row[2],
                'trans': row['translation'] if isinstance(row, dict) else row[3],
                'source': row['source'] if isinstance(row, dict) else row[4],
                'book': row['book'] if isinstance(row, dict) else row[5]
            })
        
        conn.close()
        return jsonify({"liked": liked, "saved": saved, "favorites": favorites})
    except Exception as e:
        logger.error(f"Library error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/comments/<int:verse_id>')
def get_comments(verse_id):
    try:
        conn = get_db()
        c = get_cursor(conn)
        is_postgres = DATABASE_URL and ('postgresql' in DATABASE_URL)
        
        if is_postgres:
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
            comments.append({
                "id": row['id'] if isinstance(row, dict) else row[0],
                "text": row['text'] if isinstance(row, dict) else row[3],
                "timestamp": row['timestamp'] if isinstance(row, dict) else row[4],
                "user_name": row['name'] if isinstance(row, dict) else row[7],
                "user_picture": row['picture'] if isinstance(row, dict) else row[8]
            })
        
        return jsonify(comments)
    except Exception as e:
        logger.error(f"Get comments error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/comments', methods=['POST'])
def post_comment():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    is_banned, reason, expires = check_ban_status(session['user_id'])
    if is_banned:
        if expires:
            expires_str = str(expires)[:16]
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
        
        conn = get_db()
        c = get_cursor(conn)
        is_postgres = DATABASE_URL and ('postgresql' in DATABASE_URL)
        
        if is_postgres:
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
        logger.error(f"Post comment error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/delete_comment/<int:comment_id>', methods=['DELETE'])
def delete_comment(comment_id):
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    if not session.get('is_admin'):
        return jsonify({"error": "Admin required"}), 403
    
    try:
        conn = get_db()
        c = get_cursor(conn)
        is_postgres = DATABASE_URL and ('postgresql' in DATABASE_URL)
        
        if is_postgres:
            c.execute("DELETE FROM comments WHERE id = %s", (comment_id,))
        else:
            c.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
            
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Delete comment error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/community')
def get_community_messages():
    try:
        conn = get_db()
        c = get_cursor(conn)
        is_postgres = DATABASE_URL and ('postgresql' in DATABASE_URL)
        
        if is_postgres:
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
            messages.append({
                "id": row['id'] if isinstance(row, dict) else row[0],
                "text": row['text'] if isinstance(row, dict) else row[2],
                "timestamp": row['timestamp'] if isinstance(row, dict) else row[3],
                "user_name": row['name'] if isinstance(row, dict) else row[6],
                "user_picture": row['picture'] if isinstance(row, dict) else row[7]
            })
        
        return jsonify(messages)
    except Exception as e:
        logger.error(f"Community get error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/community', methods=['POST'])
def post_community_message():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    is_banned, reason, expires = check_ban_status(session['user_id'])
    if is_banned:
        if expires:
            expires_str = str(expires)[:16]
            msg = f'You are banned until {expires_str}. Reason: {reason or "Violation"}'
        else:
            msg = f'You are permanently banned. Reason: {reason or "Violation"}'
        return jsonify({"error": msg, "banned": True}), 403
    
    try:
        data = request.get_json()
        text = data.get('text', '').strip()
        
        if not text:
            return jsonify({"error": "Empty message"}), 400
        
        conn = get_db()
        c = get_cursor(conn)
        is_postgres = DATABASE_URL and ('postgresql' in DATABASE_URL)
        
        if is_postgres:
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
        logger.error(f"Community post error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/delete_community/<int:message_id>', methods=['DELETE'])
def delete_community_message(message_id):
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    if not session.get('is_admin'):
        return jsonify({"error": "Admin required"}), 403
    
    try:
        conn = get_db()
        c = get_cursor(conn)
        is_postgres = DATABASE_URL and ('postgresql' in DATABASE_URL)
        
        if is_postgres:
            c.execute("DELETE FROM community_messages WHERE id = %s", (message_id,))
        else:
            c.execute("DELETE FROM community_messages WHERE id = ?", (message_id,))
            
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Delete community error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/check_like/<int:verse_id>')
def check_like(verse_id):
    if 'user_id' not in session:
        return jsonify({"liked": False})
    
    try:
        conn = get_db()
        c = get_cursor(conn)
        is_postgres = DATABASE_URL and ('postgresql' in DATABASE_URL)
        
        if is_postgres:
            c.execute("SELECT id FROM likes WHERE user_id = %s AND verse_id = %s", (session['user_id'], verse_id))
        else:
            c.execute("SELECT id FROM likes WHERE user_id = ? AND verse_id = ?", (session['user_id'], verse_id))
            
        liked = c.fetchone() is not None
        conn.close()
        return jsonify({"liked": liked})
    except Exception as e:
        logger.error(f"Check like error: {e}")
        return jsonify({"liked": False})

@app.route('/api/check_save/<int:verse_id>')
def check_save(verse_id):
    if 'user_id' not in session:
        return jsonify({"saved": False})
    
    try:
        conn = get_db()
        c = get_cursor(conn)
        is_postgres = DATABASE_URL and ('postgresql' in DATABASE_URL)
        
        if is_postgres:
            c.execute("SELECT id FROM saves WHERE user_id = %s AND verse_id = %s", (session['user_id'], verse_id))
        else:
            c.execute("SELECT id FROM saves WHERE user_id = ? AND verse_id = ?", (session['user_id'], verse_id))
            
        saved = c.fetchone() is not None
        conn.close()
        return jsonify({"saved": saved})
    except Exception as e:
        logger.error(f"Check save error: {e}")
        return jsonify({"saved": False})

@app.route('/api/ban_status')
def ban_status():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    is_banned, reason, expires = check_ban_status(session['user_id'])
    
    status = {
        "is_banned": is_banned,
        "reason": reason,
        "expires": str(expires) if expires else None
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
                minutes, seconds = divmod(remainder, 60)
                days = diff.days
                
                if days > 0:
                    status["time_remaining"] = f"{days}d {hours}h {minutes}m"
                else:
                    status["time_remaining"] = f"{hours}h {minutes}m"
            else:
                status["time_remaining"] = "Expired"
        except:
            status["time_remaining"] = "Unknown"
    else:
        status["time_remaining"] = None
    
    return jsonify(status)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
