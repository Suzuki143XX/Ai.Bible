from flask import Flask, render_template, jsonify, request, redirect, url_for, session, send_from_directory
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

app = Flask(__name__)
app.permanent_session_lifetime = timedelta(days=30)

@app.before_request
def make_session_permanent():
    session.permanent = True

app.secret_key = os.environ.get('SECRET_KEY', 'bible-app-secret-key-2024-keep-this-safe')

# Configuration
DATABASE_URL = os.environ.get('DATABASE_URL')
db_path = os.path.join(os.path.dirname(__file__), "bible_ios.db")

# Google OAuth
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
PUBLIC_URL = os.environ.get('PUBLIC_URL', 'http://localhost:5000')

ADMIN_CODE = "God Is All"

def get_db():
    if DATABASE_URL and DATABASE_URL.startswith('postgres'):
        import psycopg2
        conn = psycopg2.connect(DATABASE_URL)
        return conn, True
    else:
        conn = sqlite3.connect(db_path, timeout=20)
        conn.row_factory = sqlite3.Row
        return conn, False

def init_db():
    conn, is_postgres = get_db()
    c = conn.cursor()
    
    if is_postgres:
        c.execute('''CREATE TABLE IF NOT EXISTS verses 
                     (id SERIAL PRIMARY KEY, reference TEXT, text TEXT, 
                      translation TEXT, source TEXT, timestamp TEXT, book TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS users 
                     (id SERIAL PRIMARY KEY, google_id TEXT UNIQUE, email TEXT, 
                      name TEXT, picture TEXT, created_at TEXT, is_admin INTEGER DEFAULT 0)''')
        c.execute('''CREATE TABLE IF NOT EXISTS likes 
                     (id SERIAL PRIMARY KEY, user_id INTEGER, verse_id INTEGER, 
                      timestamp TEXT, UNIQUE(user_id, verse_id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS saves 
                     (id SERIAL PRIMARY KEY, user_id INTEGER, verse_id INTEGER, 
                      timestamp TEXT, UNIQUE(user_id, verse_id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS comments 
                     (id SERIAL PRIMARY KEY, user_id INTEGER, verse_id INTEGER,
                      text TEXT, timestamp TEXT)''')
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
                      timestamp TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS app_settings
                     (key TEXT PRIMARY KEY, value TEXT)''')
    else:
        c.execute('''CREATE TABLE IF NOT EXISTS verses 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, reference TEXT, text TEXT, 
                      translation TEXT, source TEXT, timestamp TEXT, book TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS users 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, google_id TEXT UNIQUE, email TEXT, 
                      name TEXT, picture TEXT, created_at TEXT, is_admin INTEGER DEFAULT 0)''')
        c.execute('''CREATE TABLE IF NOT EXISTS likes 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, verse_id INTEGER, 
                      timestamp TEXT, UNIQUE(user_id, verse_id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS saves 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, verse_id INTEGER, 
                      timestamp TEXT, UNIQUE(user_id, verse_id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS comments 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, verse_id INTEGER,
                      text TEXT, timestamp TEXT)''')
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
                      timestamp TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS app_settings
                     (key TEXT PRIMARY KEY, value TEXT)''')
    
    conn.commit()
    conn.close()

init_db()

class BibleGenerator:
    def __init__(self):
        self.running = True
        self.interval = self.load_interval()  # Load from DB
        self.current_verse = None
        self.total_verses = 0
        self.session_id = secrets.token_hex(8)
        
        self.networks = [
            {"name": "Bible-API.com", "url": "https://bible-api.com/?random=verse"},
            {"name": "labs.bible.org", "url": "https://labs.bible.org/api/?passage=random&type=json"},
        ]
        self.network_idx = 0
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        self.fetch_verse()
    
    def load_interval(self):
        """Load interval from database or default to 60"""
        try:
            conn, is_postgres = get_db()
            c = conn.cursor()
            if is_postgres:
                c.execute("SELECT value FROM app_settings WHERE key = 'interval'")
            else:
                c.execute("SELECT value FROM app_settings WHERE key = 'interval'")
            row = c.fetchone()
            conn.close()
            if row:
                return int(row[0] if isinstance(row, tuple) else row['value'])
        except:
            pass
        return 60
    
    def save_interval(self, seconds):
        """Save interval to database"""
        try:
            conn, is_postgres = get_db()
            c = conn.cursor()
            if is_postgres:
                c.execute("""
                    INSERT INTO app_settings (key, value) 
                    VALUES ('interval', %s) 
                    ON CONFLICT (key) DO UPDATE SET value = %s
                """, (str(seconds), str(seconds)))
            else:
                c.execute("""
                    INSERT OR REPLACE INTO app_settings (key, value) 
                    VALUES (?, ?)
                """, ('interval', str(seconds)))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Failed to save interval: {e}")
    
    def set_interval(self, seconds):
        self.interval = max(30, min(3600, int(seconds)))
        self.save_interval(self.interval)
        return self.interval
    
    def get_time_left(self):
        try:
            conn, is_postgres = get_db()
            c = conn.cursor()
            
            if is_postgres:
                c.execute("SELECT expires_at FROM verse_sessions WHERE session_id = %s ORDER BY id DESC LIMIT 1", 
                         (self.session_id,))
            else:
                c.execute("SELECT expires_at FROM verse_sessions WHERE session_id = ? ORDER BY id DESC LIMIT 1", 
                         (self.session_id,))
            row = c.fetchone()
            conn.close()
            
            if row:
                expires_str = row[0] if isinstance(row, tuple) else row['expires_at']
                expires = datetime.fromisoformat(str(expires_str))
                now = datetime.now()
                diff = (expires - now).total_seconds()
                return max(0, int(diff))
            return self.interval
        except Exception as e:
            print(f"Timer error: {e}")
            return self.interval
    
    def check_and_update(self):
        if self.get_time_left() <= 0:
            self.fetch_verse()
    
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
                
                conn, is_postgres = get_db()
                c = conn.cursor()
                
                if is_postgres:
                    c.execute("""
                        INSERT INTO verses (reference, text, translation, source, timestamp, book) 
                        VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING
                    """, (ref, text, trans, network["name"], datetime.now().isoformat(), book))
                else:
                    c.execute("""
                        INSERT OR IGNORE INTO verses (reference, text, translation, source, timestamp, book) 
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (ref, text, trans, network["name"], datetime.now().isoformat(), book))
                
                conn.commit()
                
                if is_postgres:
                    c.execute("SELECT id FROM verses WHERE reference = %s AND text = %s", (ref, text))
                else:
                    c.execute("SELECT id FROM verses WHERE reference = ? AND text = ?", (ref, text))
                result = c.fetchone()
                verse_id = result[0] if result else None
                
                self.session_id = secrets.token_hex(8)
                expires = datetime.fromtimestamp(time.time() + self.interval).isoformat()
                
                if is_postgres:
                    c.execute("""
                        INSERT INTO verse_sessions (verse_id, session_id, created_at, expires_at) 
                        VALUES (%s, %s, %s, %s)
                    """, (verse_id, self.session_id, datetime.now().isoformat(), expires))
                else:
                    c.execute("""
                        INSERT INTO verse_sessions (verse_id, session_id, created_at, expires_at) 
                        VALUES (?, ?, ?, ?)
                    """, (verse_id, self.session_id, datetime.now().isoformat(), expires))
                
                conn.commit()
                conn.close()
                
                self.current_verse = {
                    "id": verse_id, "ref": ref, "text": text,
                    "trans": trans, "source": network["name"], "book": book,
                    "session_id": self.session_id
                }
                self.total_verses += 1
                return True
        except Exception as e:
            print(f"Fetch error: {e}")
        
        self.network_idx = (self.network_idx + 1) % len(self.networks)
        return False

generator = BibleGenerator()

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn, is_postgres = get_db()
    c = conn.cursor()
    
    if is_postgres:
        c.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
    else:
        c.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
    user = c.fetchone()
    conn.close()
    
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    user_dict = {
        "id": user[0] if isinstance(user, tuple) else user['id'],
        "name": user[3] if isinstance(user, tuple) else user['name'],
        "email": user[2] if isinstance(user, tuple) else user['email'],
        "picture": user[4] if isinstance(user, tuple) else user['picture'],
        "is_admin": bool(user[6] if isinstance(user, tuple) else user['is_admin'])
    }
    
    # Ensure session has latest admin status
    session['is_admin'] = user_dict['is_admin']
    session.modified = True
    
    return render_template('web.html', user=user_dict, interval=generator.interval)

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/google-login')
def google_login():
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
    
    conn, is_postgres = get_db()
    c = conn.cursor()
    
    if is_postgres:
        c.execute("SELECT * FROM users WHERE google_id = %s", (google_id,))
    else:
        c.execute("SELECT * FROM users WHERE google_id = ?", (google_id,))
    user = c.fetchone()
    
    if not user:
        if is_postgres:
            c.execute("""
                INSERT INTO users (google_id, email, name, picture, created_at, is_admin) 
                VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING
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
    
    conn.close()
    
    if user:
        session['user_id'] = user[0] if isinstance(user, tuple) else user['id']
        session['user_name'] = user[3] if isinstance(user, tuple) else user['name']
        session['is_admin'] = bool(user[6] if isinstance(user, tuple) else user['is_admin'])
        session.modified = True
    
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/current')
def get_current():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    generator.check_and_update()
    
    return jsonify({
        "verse": generator.current_verse,
        "countdown": generator.get_time_left(),
        "interval": generator.interval,
        "is_admin": session.get('is_admin', False)
    })

@app.route('/api/set_interval', methods=['POST'])
def set_interval():
    # Strict admin check
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    if not session.get('is_admin'):
        return jsonify({"error": "Admin privileges required"}), 403
    
    data = request.get_json()
    if not data or 'interval' not in data:
        return jsonify({"error": "Interval value required"}), 400
    
    try:
        new_interval = generator.set_interval(int(data['interval']))
        return jsonify({
            "success": True, 
            "interval": new_interval,
            "message": f"Refresh interval set to {new_interval} seconds"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/verify_admin', methods=['POST'])
def verify_admin():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    data = request.get_json()
    code = data.get('code', '').strip()
    
    if code == ADMIN_CODE:
        conn, is_postgres = get_db()
        c = conn.cursor()
        
        if is_postgres:
            c.execute("UPDATE users SET is_admin = 1 WHERE id = %s", (session['user_id'],))
        else:
            c.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (session['user_id'],))
        
        conn.commit()
        conn.close()
        
        # Update session immediately
        session['is_admin'] = True
        session.modified = True
        
        return jsonify({
            "success": True, 
            "is_admin": True,
            "message": "Admin privileges granted"
        })
    else:
        return jsonify({
            "success": False, 
            "error": "Invalid admin code"
        }), 403

@app.route('/api/check_admin')
def check_admin():
    if 'user_id' not in session:
        return jsonify({"is_admin": False, "logged_in": False})
    
    # Verify against database to ensure sync
    conn, is_postgres = get_db()
    c = conn.cursor()
    
    if is_postgres:
        c.execute("SELECT is_admin FROM users WHERE id = %s", (session['user_id'],))
    else:
        c.execute("SELECT is_admin FROM users WHERE id = ?", (session['user_id'],))
    
    row = c.fetchone()
    conn.close()
    
    is_admin = False
    if row:
        is_admin = bool(row[0] if isinstance(row, tuple) else row['is_admin'])
        if session.get('is_admin') != is_admin:
            session['is_admin'] = is_admin
            session.modified = True
    
    return jsonify({
        "is_admin": is_admin,
        "logged_in": True
    })

@app.route('/api/stats')
def get_stats():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    conn, is_postgres = get_db()
    c = conn.cursor()
    
    c.execute("SELECT COUNT(*) FROM verses")
    total = c.fetchone()[0]
    
    if is_postgres:
        c.execute("SELECT COUNT(*) FROM likes WHERE user_id = %s", (session['user_id'],))
        liked = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM saves WHERE user_id = %s", (session['user_id'],))
        saved = c.fetchone()[0]
    else:
        c.execute("SELECT COUNT(*) FROM likes WHERE user_id = ?", (session['user_id'],))
        liked = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM saves WHERE user_id = ?", (session['user_id'],))
        saved = c.fetchone()[0]
    
    conn.close()
    
    return jsonify({
        "total_verses": total,
        "liked": liked,
        "saved": saved,
        "is_admin": session.get('is_admin', False)
    })

@app.route('/api/like', methods=['POST'])
def like_verse():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    data = request.get_json()
    verse_id = data.get('verse_id')
    
    conn, is_postgres = get_db()
    c = conn.cursor()
    
    try:
        if is_postgres:
            c.execute("SELECT id FROM likes WHERE user_id = %s AND verse_id = %s", 
                     (session['user_id'], verse_id))
            if c.fetchone():
                c.execute("DELETE FROM likes WHERE user_id = %s AND verse_id = %s", 
                         (session['user_id'], verse_id))
                liked = False
            else:
                c.execute("INSERT INTO likes (user_id, verse_id, timestamp) VALUES (%s, %s, %s)",
                         (session['user_id'], verse_id, datetime.now().isoformat()))
                liked = True
        else:
            c.execute("SELECT id FROM likes WHERE user_id = ? AND verse_id = ?", 
                     (session['user_id'], verse_id))
            if c.fetchone():
                c.execute("DELETE FROM likes WHERE user_id = ? AND verse_id = ?", 
                         (session['user_id'], verse_id))
                liked = False
            else:
                c.execute("INSERT INTO likes (user_id, verse_id, timestamp) VALUES (?, ?, ?)",
                         (session['user_id'], verse_id, datetime.now().isoformat()))
                liked = True
        
        conn.commit()
        conn.close()
        return jsonify({"liked": liked})
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500

@app.route('/api/library')
def get_library():
    if 'user_id' not in session:
        return jsonify({"liked": [], "saved": []})
    
    conn, is_postgres = get_db()
    c = conn.cursor()
    
    if is_postgres:
        c.execute("""
            SELECT v.id, v.reference, v.text, v.translation, v.book
            FROM verses v 
            JOIN likes l ON v.id = l.verse_id 
            WHERE l.user_id = %s 
            ORDER BY l.timestamp DESC
        """, (session['user_id'],))
    else:
        c.execute("""
            SELECT v.id, v.reference, v.text, v.translation, v.book
            FROM verses v 
            JOIN likes l ON v.id = l.verse_id 
            WHERE l.user_id = ? 
            ORDER BY l.timestamp DESC
        """, (session['user_id'],))
    
    liked = [{
        "id": row[0] if isinstance(row, tuple) else row['id'],
        "ref": row[1] if isinstance(row, tuple) else row['reference'],
        "text": row[2] if isinstance(row, tuple) else row['text'],
        "trans": row[3] if isinstance(row, tuple) else row['translation'],
        "book": row[4] if isinstance(row, tuple) else row['book']
    } for row in c.fetchall()]
    
    if is_postgres:
        c.execute("""
            SELECT v.id, v.reference, v.text, v.translation, v.book
            FROM verses v 
            JOIN saves s ON v.id = s.verse_id 
            WHERE s.user_id = %s 
            ORDER BY s.timestamp DESC
        """, (session['user_id'],))
    else:
        c.execute("""
            SELECT v.id, v.reference, v.text, v.translation, v.book
            FROM verses v 
            JOIN saves s ON v.id = s.verse_id 
            WHERE s.user_id = ? 
            ORDER BY s.timestamp DESC
        """, (session['user_id'],))
    
    saved = [{
        "id": row[0] if isinstance(row, tuple) else row['id'],
        "ref": row[1] if isinstance(row, tuple) else row['reference'],
        "text": row[2] if isinstance(row, tuple) else row['text'],
        "trans": row[3] if isinstance(row, tuple) else row['translation'],
        "book": row[4] if isinstance(row, tuple) else row['book']
    } for row in c.fetchall()]
    
    conn.close()
    return jsonify({"liked": liked, "saved": saved})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
