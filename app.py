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

# Production: Use environment variables
app.secret_key = os.environ.get("SECRET_KEY", "dev-key-replace-in-production")
app.permanent_session_lifetime = timedelta(days=30)

@app.before_request
def make_session_permanent():
    session.permanent = True

# Production: Environment-based config
PUBLIC_URL = os.environ.get("RENDER_EXTERNAL_URL", "http://localhost:5000")
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
print(f"DEBUG: CLIENT_ID loaded: {GOOGLE_CLIENT_ID[:20]}..." if GOOGLE_CLIENT_ID else "DEBUG: CLIENT_ID is EMPTY!")
print(f"DEBUG: CLIENT_SECRET loaded: {GOOGLE_CLIENT_SECRET[:10]}..." if GOOGLE_CLIENT_SECRET else "DEBUG: CLIENT_SECRET is EMPTY!")
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
ADMIN_CODE = os.environ.get("ADMIN_CODE", "God Is All")

# Database setup (Note: SQLite is ephemeral on Render free tier)
db_path = os.path.join(os.path.dirname(__file__), "bible_ios.db")

def get_db():
    conn = sqlite3.connect(db_path, timeout=20)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    
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
    
    try:
        c.execute("SELECT is_admin FROM users LIMIT 1")
    except sqlite3.OperationalError:
        c.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
        print("Migrated: Added is_admin column to users table")
    
    conn.commit()
    conn.close()

init_db()

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
                
                conn = get_db()
                c = conn.cursor()
                c.execute("INSERT OR IGNORE INTO verses (reference, text, translation, source, timestamp, book) VALUES (?, ?, ?, ?, ?, ?)",
                          (ref, text, trans, network["name"], datetime.now().isoformat(), book))
                conn.commit()
                c.execute("SELECT id FROM verses WHERE reference = ? AND text = ?", (ref, text))
                result = c.fetchone()
                verse_id = result['id'] if result else None
                
                self.session_id = secrets.token_hex(8)
                expires = datetime.fromtimestamp(time.time() + self.interval).isoformat()
                c.execute("INSERT INTO verse_sessions (verse_id, session_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                          (verse_id, self.session_id, datetime.now().isoformat(), expires))
                
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
        conn = get_db()
        c = conn.cursor()
        
        c.execute("""
            SELECT DISTINCT v.book FROM verses v 
            JOIN likes l ON v.id = l.verse_id 
            WHERE l.user_id = ?
            UNION
            SELECT DISTINCT v.book FROM verses v 
            JOIN saves s ON v.id = s.verse_id 
            WHERE s.user_id = ?
        """, (user_id, user_id))
        
        preferred_books = [row['book'] for row in c.fetchall()]
        
        if preferred_books:
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
            c.execute("""
                SELECT * FROM verses 
                WHERE id NOT IN (SELECT verse_id FROM likes WHERE user_id = ?)
                ORDER BY RANDOM() LIMIT 1
            """, (user_id,))
        
        row = c.fetchone()
        conn.close()
        
        if row:
            return {
                "id": row['id'], "ref": row['reference'], "text": row['text'],
                "trans": row['translation'], "book": row['book'],
                "reason": f"Because you like {row['book']}" if preferred_books else "Recommended for you"
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
    
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
    user = c.fetchone()
    
    c.execute("SELECT COUNT(*) as count FROM verses")
    total_verses = c.fetchone()['count']
    c.execute("SELECT COUNT(*) as count FROM likes WHERE user_id = ?", (session['user_id'],))
    liked_count = c.fetchone()['count']
    c.execute("SELECT COUNT(*) as count FROM saves WHERE user_id = ?", (session['user_id'],))
    saved_count = c.fetchone()['count']
    
    conn.close()
    
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    return render_template('web.html', 
                         user={"id": user['id'], "name": user['name'], "email": user['email'], "picture": user['picture']},
                         stats={"total_verses": total_verses, "liked": liked_count, "saved": saved_count})

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/google-login')
def google_login():
    if not GOOGLE_CLIENT_ID:
        return "Google OAuth not configured. Set GOOGLE_CLIENT_ID environment variable.", 500
        
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
    
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE google_id = ?", (google_id,))
    user = c.fetchone()
    
    if not user:
        c.execute("INSERT INTO users (google_id, email, name, picture, created_at, is_admin) VALUES (?, ?, ?, ?, ?, ?)",
                  (google_id, email, name, picture, datetime.now().isoformat(), 0))
        conn.commit()
        c.execute("SELECT * FROM users WHERE google_id = ?", (google_id,))
        user = c.fetchone()
    
    conn.close()
    session['user_id'] = user['id']
    session['user_name'] = user['name']
    session['user_picture'] = user['picture']
    session['is_admin'] = bool(user['is_admin']) if user.keys() and 'is_admin' in user.keys() else False
    return redirect(url_for('index'))   

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/current')
def get_current():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
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
    
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT created_at, is_admin FROM users WHERE id = ?", (session['user_id'],))
    row = c.fetchone()
    conn.close()
    
    if row:
        is_admin_val = bool(row['is_admin']) if row.keys() and 'is_admin' in row.keys() else False
        return jsonify({
            "created_at": row['created_at'],
            "is_admin": is_admin_val,
            "session_admin": session.get('is_admin', False)
        })
    return jsonify({"created_at": None, "is_admin": False, "session_admin": False}) 

@app.route('/api/verify_admin', methods=['POST'])
def verify_admin():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    data = request.get_json()
    code = data.get('code', '')
    
    if code == ADMIN_CODE:
        conn = get_db()
        c = conn.cursor()
        c.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (session['user_id'],))
        conn.commit()
        conn.close()
        
        session['is_admin'] = True
        return jsonify({"success": True, "role": ">Admin<"})
    else:
        return jsonify({"success": False, "error": "Wrong code"})

@app.route('/api/stats')
def get_stats():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) as count FROM verses")
    total = c.fetchone()['count']
    c.execute("SELECT COUNT(*) as count FROM likes WHERE user_id = ?", (session['user_id'],))
    liked = c.fetchone()['count']
    c.execute("SELECT COUNT(*) as count FROM saves WHERE user_id = ?", (session['user_id'],))
    saved = c.fetchone()['count']
    c.execute("SELECT COUNT(*) as count FROM comments WHERE user_id = ?", (session['user_id'],))
    comments = c.fetchone()['count']
    conn.close()
    return jsonify({"total_verses": total, "liked": liked, "saved": saved, "comments": comments})

@app.route('/api/like', methods=['POST'])
def like_verse():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    data = request.get_json()
    verse_id = data.get('verse_id')
    conn = get_db()
    c = conn.cursor()
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
    data = request.get_json()
    verse_id = data.get('verse_id')
    conn = get_db()
    c = conn.cursor()
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
    conn = get_db()
    c = conn.cursor()
    
    c.execute("""
        SELECT v.id, v.reference, v.text, v.translation, v.source, v.book, l.timestamp as liked_at
        FROM verses v 
        JOIN likes l ON v.id = l.verse_id 
        WHERE l.user_id = ? 
        ORDER BY l.timestamp DESC
    """, (session['user_id'],))
    liked = [{"id": row['id'], "ref": row['reference'], "text": row['text'], "trans": row['translation'], 
              "source": row['source'], "book": row['book'], "liked_at": row['liked_at'], "saved_at": None} for row in c.fetchall()]
    
    c.execute("""
        SELECT v.id, v.reference, v.text, v.translation, v.source, v.book, s.timestamp as saved_at
        FROM verses v 
        JOIN saves s ON v.id = s.verse_id 
        WHERE s.user_id = ? 
        ORDER BY s.timestamp DESC
    """, (session['user_id'],))
    saved = [{"id": row['id'], "ref": row['reference'], "text": row['text'], "trans": row['translation'], 
              "source": row['source'], "book": row['book'], "liked_at": None, "saved_at": row['saved_at']} for row in c.fetchall()]
    
    c.execute("""
        SELECT c.id, c.name, c.color, COUNT(vc.verse_id) as count 
        FROM collections c
        LEFT JOIN verse_collections vc ON c.id = vc.collection_id
        WHERE c.user_id = ?
        GROUP BY c.id
    """, (session['user_id'],))
    
    collections = []
    for row in c.fetchall():
        c.execute("""
            SELECT v.id, v.reference, v.text FROM verses v
            JOIN verse_collections vc ON v.id = vc.verse_id
            WHERE vc.collection_id = ?
        """, (row['id'],))
        verses = [{"id": v['id'], "ref": v['reference'], "text": v['text']} for v in c.fetchall()]
        collections.append({
            "id": row['id'], "name": row['name'], "color": row['color'], 
            "count": row['count'], "verses": verses
        })
    
    conn.close()
    return jsonify({"liked": liked, "saved": saved, "collections": collections})

@app.route('/api/collections/add', methods=['POST'])
def add_to_collection():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    data = request.get_json()
    collection_id = data.get('collection_id')
    verse_id = data.get('verse_id')
    
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO verse_collections (collection_id, verse_id) VALUES (?, ?)",
                  (collection_id, verse_id))
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"success": False, "error": "Already in collection"})

@app.route('/api/collections/create', methods=['POST'])
def create_collection():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    data = request.get_json()
    name = data.get('name')
    color = data.get('color', '#0A84FF')
    
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO collections (user_id, name, color, created_at) VALUES (?, ?, ?, ?)",
              (session['user_id'], name, color, datetime.now().isoformat()))
    conn.commit()
    new_id = c.lastrowid
    conn.close()
    return jsonify({"id": new_id, "name": name, "color": color, "count": 0, "verses": []})

@app.route('/api/collections/delete', methods=['POST'])
def delete_collection():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    data = request.get_json()
    collection_id = data.get('collection_id')
    
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT user_id FROM collections WHERE id = ?", (collection_id,))
    row = c.fetchone()
    if not row or row['user_id'] != session['user_id']:
        conn.close()
        return jsonify({"error": "Unauthorized"}), 403
    
    c.execute("DELETE FROM verse_collections WHERE collection_id = ?", (collection_id,))
    c.execute("DELETE FROM collections WHERE id = ?", (collection_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route('/api/recommendations')
def get_recommendations():
    if 'user_id' not in session:
        return jsonify([])
    conn = get_db()
    c = conn.cursor()
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
    rec = generator.generate_smart_recommendation(session['user_id'])
    if rec:
        return jsonify({"success": True, "recommendation": rec})
    return jsonify({"success": False})

@app.route('/api/comments/<int:verse_id>')
def get_comments(verse_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT c.*, u.name, u.picture 
        FROM comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.verse_id = ?
        ORDER BY c.timestamp DESC
    """, (verse_id,))
    comments = [{
        "id": row['id'],
        "text": row['text'],
        "timestamp": row['timestamp'],
        "user_name": row['name'],
        "user_picture": row['picture'],
        "user_id": row['user_id']
    } for row in c.fetchall()]
    conn.close()
    return jsonify(comments)

@app.route('/api/comments', methods=['POST'])
def post_comment():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    data = request.get_json()
    verse_id = data.get('verse_id')
    text = data.get('text', '').strip()
    
    if not text:
        return jsonify({"error": "Empty comment"}), 400
    
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO comments (user_id, verse_id, text, timestamp, google_name, google_picture) VALUES (?, ?, ?, ?, ?, ?)",
              (session['user_id'], verse_id, text, datetime.now().isoformat(), 
               session.get('user_name'), session.get('user_picture')))
    conn.commit()
    
    comment_id = c.lastrowid
    c.execute("SELECT c.*, u.name, u.picture FROM comments c JOIN users u ON c.user_id = u.id WHERE c.id = ?", (comment_id,))
    row = c.fetchone()
    conn.close()
    
    return jsonify({
        "id": row['id'],
        "text": row['text'],
        "timestamp": row['timestamp'],
        "user_name": row['name'],
        "user_picture": row['picture'],
        "user_id": row['user_id']
    })

@app.route('/api/admin/delete_comment/<int:comment_id>', methods=['DELETE'])
def delete_comment(comment_id):
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    if not session.get('is_admin'):
        return jsonify({"error": "Admin required"}), 403
    
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
    conn.commit()
    conn.close()
    
    return jsonify({"success": True})

@app.route('/api/community')
def get_community_messages():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT m.*, u.name, u.picture 
        FROM community_messages m
        JOIN users u ON m.user_id = u.id
        ORDER BY m.timestamp DESC
        LIMIT 100
    """)
    messages = [{
        "id": row['id'],
        "text": row['text'],
        "timestamp": row['timestamp'],
        "user_name": row['name'],
        "user_picture": row['picture'],
        "user_id": row['user_id']
    } for row in c.fetchall()]
    conn.close()
    return jsonify(messages)

@app.route('/api/community', methods=['POST'])
def post_community_message():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    data = request.get_json()
    text = data.get('text', '').strip()
    
    if not text:
        return jsonify({"error": "Empty message"}), 400
    
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO community_messages (user_id, text, timestamp, google_name, google_picture) VALUES (?, ?, ?, ?, ?)",
              (session['user_id'], text, datetime.now().isoformat(), 
               session.get('user_name'), session.get('user_picture')))
    conn.commit()
    
    message_id = c.lastrowid
    c.execute("SELECT m.*, u.name, u.picture FROM community_messages m JOIN users u ON m.user_id = u.id WHERE m.id = ?", (message_id,))
    row = c.fetchone()
    conn.close()
    
    return jsonify({
        "id": row['id'],
        "text": row['text'],
        "timestamp": row['timestamp'],
        "user_name": row['name'],
        "user_picture": row['picture'],
        "user_id": row['user_id']
    })

@app.route('/api/admin/delete_community/<int:message_id>', methods=['DELETE'])
def delete_community_message(message_id):
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    if not session.get('is_admin'):
        return jsonify({"error": "Admin required"}), 403
    
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM community_messages WHERE id = ?", (message_id,))
    conn.commit()
    conn.close()
    
    return jsonify({"success": True})

@app.route('/api/check_like/<int:verse_id>')
def check_like(verse_id):
    if 'user_id' not in session:
        return jsonify({"liked": False})
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM likes WHERE user_id = ? AND verse_id = ?", (session['user_id'], verse_id))
    liked = c.fetchone() is not None
    conn.close()
    return jsonify({"liked": liked})

@app.route('/api/check_save/<int:verse_id>')
def check_save(verse_id):
    if 'user_id' not in session:
        return jsonify({"saved": False})
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM saves WHERE user_id = ? AND verse_id = ?", (session['user_id'], verse_id))
    saved = c.fetchone() is not None
    conn.close()
    return jsonify({"saved": saved})

# Production entry point for Render
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))

    app.run(host='0.0.0.0', port=port, debug=False)
