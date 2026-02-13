from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
import psycopg2
import psycopg2.extras
from datetime import datetime, timedelta
import os
import requests
import json
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'bible-ai-secret-key-v2')

# Database Configuration
DATABASE_URL = os.environ.get('DATABASE_URL', "postgresql://bible_db_2y32_user:aw2y7YQyqKZTPLCPaUcOs5wybLEJpqQX@dpg-d67hk9ggjchc73amsghg-a.oregon-postgres.render.com/bible_db_2y32")

def get_db():
    conn = psycopg2.connect(DATABASE_URL, sslmode='require')
    return conn

def check_ban_status(user_id):
    """Check if user is banned and return ban details"""
    try:
        conn = get_db()
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        c.execute("""
            SELECT is_banned, ban_expires_at, ban_reason, role
            FROM users 
            WHERE id = %s AND is_banned = TRUE
        """, (user_id,))
        result = c.fetchone()
        conn.close()
        
        if result:
            # Auto-unban if expired
            if result['ban_expires_at'] and result['ban_expires_at'] < datetime.now():
                conn = get_db()
                c = conn.cursor()
                c.execute("""
                    UPDATE users 
                    SET is_banned = FALSE, ban_expires_at = NULL, ban_reason = NULL 
                    WHERE id = %s
                """, (user_id,))
                conn.commit()
                conn.close()
                return None
            
            # Format duration text
            expires = result['ban_expires_at']
            if expires:
                remaining = expires - datetime.now()
                hours = int(remaining.total_seconds() / 3600)
                if hours < 1:
                    duration_text = "Less than 1hr"
                elif hours < 24:
                    duration_text = f"{hours}hr"
                elif hours < 168:
                    days = hours // 24
                    duration_text = f"{days}day"
                elif hours < 720:
                    weeks = hours // 168
                    duration_text = f"{weeks}week"
                else:
                    duration_text = "1month"
            else:
                duration_text = "Permanent"
                
            return {
                'is_banned': True,
                'reason': result['ban_reason'] or 'Violation of community guidelines',
                'expires_at': expires,
                'duration_text': duration_text,
                'role': result['role']
            }
        return None
    except Exception as e:
        print(f"Ban check error: {e}")
        return None

def init_db():
    """Initialize database tables if they don't exist"""
    try:
        conn = get_db()
        c = conn.cursor()
        
        # Users table with ban support
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                picture TEXT,
                google_id VARCHAR(100),
                role VARCHAR(20) DEFAULT 'user',
                is_banned BOOLEAN DEFAULT FALSE,
                ban_expires_at TIMESTAMP,
                ban_reason TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Verses table
        c.execute("""
            CREATE TABLE IF NOT EXISTS verses (
                id SERIAL PRIMARY KEY,
                reference VARCHAR(100) NOT NULL,
                text TEXT NOT NULL,
                translation VARCHAR(50) DEFAULT 'KJV',
                book VARCHAR(50),
                chapter INTEGER,
                verse INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Comments table
        c.execute("""
            CREATE TABLE IF NOT EXISTS comments (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                verse_id INTEGER REFERENCES verses(id) ON DELETE CASCADE,
                text TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_deleted BOOLEAN DEFAULT FALSE
            )
        """)
        
        # Likes table
        c.execute("""
            CREATE TABLE IF NOT EXISTS liked_verses (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                verse_id INTEGER REFERENCES verses(id) ON DELETE CASCADE,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, verse_id)
            )
        """)
        
        # Saved verses table
        c.execute("""
            CREATE TABLE IF NOT EXISTS saved_verses (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                verse_id INTEGER REFERENCES verses(id) ON DELETE CASCADE,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, verse_id)
            )
        """)
        
        # Community messages table
        c.execute("""
            CREATE TABLE IF NOT EXISTS community_messages (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                message TEXT NOT NULL,
                category VARCHAR(50) DEFAULT 'general',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_deleted BOOLEAN DEFAULT FALSE
            )
        """)
        
        # Activity logs for heatmaps
        c.execute("""
            CREATE TABLE IF NOT EXISTS user_activity (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                activity_type VARCHAR(50),
                details JSONB,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Audit logs (sync with admin panel)
        c.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id SERIAL PRIMARY KEY,
                admin_id INTEGER REFERENCES users(id),
                action VARCHAR(50),
                target_user_id INTEGER REFERENCES users(id),
                details JSONB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        conn.close()
        print("✓ Database initialized successfully")
    except Exception as e:
        print(f"Database initialization error: {e}")

def log_activity(user_id, activity_type, details=None):
    """Log user activity for analytics"""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("""
            INSERT INTO user_activity (user_id, activity_type, details)
            VALUES (%s, %s, %s)
        """, (user_id, activity_type, json.dumps(details) if details else None))
        
        # Update last_active
        c.execute("""
            UPDATE users SET last_active = NOW() WHERE id = %s
        """, (user_id,))
        
        conn.commit()
        conn.close()
    except:
        pass

# ==================== ROUTES ====================

@app.route('/')
def index():
    return render_template('web.html')

@app.route('/api/generate', methods=['POST'])
def generate():
    """Generate/Fetch Bible verses - FIXED VERSION"""
    try:
        data = request.get_json()
        query_type = data.get('type', 'random')
        reference = data.get('reference', '').strip()
        
        conn = get_db()
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        if query_type == 'random':
            c.execute("SELECT * FROM verses ORDER BY RANDOM() LIMIT 1")
        elif query_type == 'search':
            if not reference:
                return jsonify({'success': False, 'error': 'Search term required'})
            c.execute("""
                SELECT * FROM verses 
                WHERE reference ILIKE %s OR text ILIKE %s OR book ILIKE %s 
                LIMIT 10
            """, (f'%{reference}%', f'%{reference}%', f'%{reference}%'))
        elif query_type == 'specific':
            if not reference:
                return jsonify({'success': False, 'error': 'Reference required'})
            c.execute("SELECT * FROM verses WHERE reference ILIKE %s", (f'%{reference}%',))
        else:
            c.execute("SELECT * FROM verses ORDER BY RANDOM() LIMIT 1")
            
        results = c.fetchall()
        conn.close()
        
        if not results:
            return jsonify({'success': True, 'verses': [], 'message': 'No verses found'})
        
        return jsonify({
            'success': True,
            'verses': [dict(row) for row in results],
            'count': len(results)
        })
    except Exception as e:
        print(f"Generate error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/verses/<int:verse_id>')
def get_verse(verse_id):
    """Get specific verse by ID"""
    try:
        conn = get_db()
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        c.execute("SELECT * FROM verses WHERE id = %s", (verse_id,))
        verse = c.fetchone()
        conn.close()
        
        if verse:
            return jsonify({'success': True, 'verse': dict(verse)})
        return jsonify({'success': False, 'error': 'Verse not found'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/comments', methods=['GET', 'POST'])
def comments():
    """Handle comments with ban enforcement"""
    conn = get_db()
    c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    if request.method == 'GET':
        verse_id = request.args.get('verse_id')
        user_id = request.args.get('user_id')
        
        try:
            if verse_id:
                c.execute("""
                    SELECT c.*, c.timestamp as timestamp, 
                           u.name, u.picture, u.role, u.is_banned
                    FROM comments c 
                    JOIN users u ON c.user_id = u.id 
                    WHERE c.verse_id = %s AND c.is_deleted = FALSE
                    ORDER BY c.timestamp DESC
                """, (verse_id,))
            elif user_id:
                c.execute("""
                    SELECT c.*, c.timestamp as timestamp,
                           u.name, u.picture, u.role,
                           v.reference as verse_reference
                    FROM comments c 
                    JOIN users u ON c.user_id = u.id 
                    JOIN verses v ON c.verse_id = v.id
                    WHERE c.user_id = %s AND c.is_deleted = FALSE
                    ORDER BY c.timestamp DESC
                """, (user_id,))
            else:
                c.execute("""
                    SELECT c.*, c.timestamp as timestamp,
                           u.name, u.picture, u.role,
                           v.reference as verse_reference
                    FROM comments c 
                    JOIN users u ON c.user_id = u.id 
                    JOIN verses v ON c.verse_id = v.id
                    WHERE c.is_deleted = FALSE
                    ORDER BY c.timestamp DESC LIMIT 50
                """)
            results = c.fetchall()
            conn.close()
            return jsonify({
                'success': True, 
                'comments': [dict(row) for row in results]
            })
        except Exception as e:
            conn.close()
            return jsonify({'success': False, 'error': str(e)})
    
    elif request.method == 'POST':
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not logged in'})
        
        user_id = session['user_id']
        
        # CRITICAL: Check ban status before allowing comment
        ban_info = check_ban_status(user_id)
        if ban_info:
            return jsonify({
                'success': False, 
                'error': f'You are banned: {ban_info["reason"]}',
                'ban_info': ban_info,
                'banned': True
            })
        
        data = request.get_json()
        verse_id = data.get('verse_id')
        text = data.get('text', '').strip()
        
        if not text:
            return jsonify({'success': False, 'error': 'Comment cannot be empty'})
        
        if len(text) > 1000:
            return jsonify({'success': False, 'error': 'Comment too long (max 1000 chars)'})
        
        try:
            c.execute("""
                INSERT INTO comments (user_id, verse_id, text, timestamp) 
                VALUES (%s, %s, %s, NOW()) RETURNING id
            """, (user_id, verse_id, text))
            new_id = c.fetchone()['id']
            conn.commit()
            conn.close()
            
            log_activity(user_id, 'comment', {'verse_id': verse_id})
            
            return jsonify({
                'success': True, 
                'id': new_id,
                'message': 'Comment posted successfully'
            })
        except Exception as e:
            conn.close()
            return jsonify({'success': False, 'error': str(e)})

@app.route('/api/comments/count')
def comments_count():
    """Get comment counts - FIXED"""
    try:
        conn = get_db()
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        verse_id = request.args.get('verse_id')
        user_id = request.args.get('user_id')
        
        if verse_id:
            c.execute("""
                SELECT COUNT(*) as count 
                FROM comments 
                WHERE verse_id = %s AND is_deleted = FALSE
            """, (verse_id,))
        elif user_id:
            c.execute("""
                SELECT COUNT(*) as count 
                FROM comments 
                WHERE user_id = %s AND is_deleted = FALSE
            """, (user_id,))
        else:
            c.execute("SELECT COUNT(*) as count FROM comments WHERE is_deleted = FALSE")
            
        result = c.fetchone()
        conn.close()
        return jsonify({'success': True, 'count': result['count']})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/comments/<int:comment_id>', methods=['DELETE'])
def delete_comment(comment_id):
    """Delete own comment or moderator delete"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'})
    
    user_id = session['user_id']
    
    try:
        conn = get_db()
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Check if user owns comment or is mod/admin
        c.execute("SELECT user_id FROM comments WHERE id = %s", (comment_id,))
        comment = c.fetchone()
        
        if not comment:
            conn.close()
            return jsonify({'success': False, 'error': 'Comment not found'})
        
        # Check if user is owner or admin/mod
        c.execute("SELECT role FROM users WHERE id = %s", (user_id,))
        user = c.fetchone()
        
        if comment['user_id'] != user_id and user['role'] not in ['mod', 'admin', 'owner', 'co_owner']:
            conn.close()
            return jsonify({'success': False, 'error': 'Permission denied'})
        
        c.execute("UPDATE comments SET is_deleted = TRUE WHERE id = %s", (comment_id,))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Comment deleted'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/likes', methods=['GET', 'POST', 'DELETE'])
def handle_likes():
    """Handle verse likes"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'})
    
    user_id = session['user_id']
    conn = get_db()
    c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    if request.method == 'GET':
        verse_id = request.args.get('verse_id')
        try:
            if verse_id:
                c.execute("""
                    SELECT COUNT(*) as count FROM liked_verses WHERE verse_id = %s
                """, (verse_id,))
                count = c.fetchone()['count']
                
                c.execute("""
                    SELECT id FROM liked_verses WHERE user_id = %s AND verse_id = %s
                """, (user_id, verse_id))
                liked = c.fetchone() is not None
                
                conn.close()
                return jsonify({'success': True, 'count': count, 'liked': liked})
            else:
                c.execute("""
                    SELECT v.*, l.timestamp as liked_at
                    FROM liked_verses l
                    JOIN verses v ON l.verse_id = v.id
                    WHERE l.user_id = %s
                    ORDER BY l.timestamp DESC
                """, (user_id,))
                verses = c.fetchall()
                conn.close()
                return jsonify({'success': True, 'verses': [dict(v) for v in verses]})
        except Exception as e:
            conn.close()
            return jsonify({'success': False, 'error': str(e)})
    
    elif request.method == 'POST':
        verse_id = request.get_json().get('verse_id')
        try:
            c.execute("""
                INSERT INTO liked_verses (user_id, verse_id)
                VALUES (%s, %s)
                ON CONFLICT (user_id, verse_id) DO NOTHING
            """, (user_id, verse_id))
            conn.commit()
            
            c.execute("""
                SELECT COUNT(*) as count FROM liked_verses WHERE verse_id = %s
            """, (verse_id,))
            count = c.fetchone()['count']
            conn.close()
            
            log_activity(user_id, 'like', {'verse_id': verse_id})
            return jsonify({'success': True, 'count': count})
        except Exception as e:
            conn.close()
            return jsonify({'success': False, 'error': str(e)})
    
    elif request.method == 'DELETE':
        verse_id = request.args.get('verse_id')
        try:
            c.execute("""
                DELETE FROM liked_verses WHERE user_id = %s AND verse_id = %s
            """, (user_id, verse_id))
            conn.commit()
            
            c.execute("""
                SELECT COUNT(*) as count FROM liked_verses WHERE verse_id = %s
            """, (verse_id,))
            count = c.fetchone()['count']
            conn.close()
            
            return jsonify({'success': True, 'count': count})
        except Exception as e:
            conn.close()
            return jsonify({'success': False, 'error': str(e)})

@app.route('/api/saves', methods=['GET', 'POST', 'DELETE'])
def handle_saves():
    """Handle saved verses"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'})
    
    user_id = session['user_id']
    conn = get_db()
    c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    if request.method == 'GET':
        try:
            c.execute("""
                SELECT v.*, s.timestamp as saved_at
                FROM saved_verses s
                JOIN verses v ON s.verse_id = v.id
                WHERE s.user_id = %s
                ORDER BY s.timestamp DESC
            """, (user_id,))
            verses = c.fetchall()
            conn.close()
            return jsonify({'success': True, 'verses': [dict(v) for v in verses]})
        except Exception as e:
            conn.close()
            return jsonify({'success': False, 'error': str(e)})
    
    elif request.method == 'POST':
        verse_id = request.get_json().get('verse_id')
        try:
            c.execute("""
                INSERT INTO saved_verses (user_id, verse_id)
                VALUES (%s, %s)
                ON CONFLICT (user_id, verse_id) DO NOTHING
            """, (user_id, verse_id))
            conn.commit()
            conn.close()
            
            log_activity(user_id, 'save', {'verse_id': verse_id})
            return jsonify({'success': True})
        except Exception as e:
            conn.close()
            return jsonify({'success': False, 'error': str(e)})
    
    elif request.method == 'DELETE':
        verse_id = request.args.get('verse_id')
        try:
            c.execute("""
                DELETE FROM saved_verses WHERE user_id = %s AND verse_id = %s
            """, (user_id, verse_id))
            conn.commit()
            conn.close()
            return jsonify({'success': True})
        except Exception as e:
            conn.close()
            return jsonify({'success': False, 'error': str(e)})

@app.route('/api/user/profile')
def user_profile():
    """Get user profile with ban status - FIXED"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'})
    
    user_id = session['user_id']
    conn = get_db()
    c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    try:
        # Get user stats
        c.execute("""
            SELECT 
                u.id, u.name, u.email, u.picture, u.role, 
                u.created_at, u.is_banned, u.ban_reason, u.ban_expires_at,
                (SELECT COUNT(*) FROM comments WHERE user_id = u.id AND is_deleted = FALSE) as comment_count,
                (SELECT COUNT(*) FROM saved_verses WHERE user_id = u.id) as saved_count,
                (SELECT COUNT(*) FROM liked_verses WHERE user_id = u.id) as liked_count,
                (SELECT COUNT(*) FROM community_messages WHERE user_id = u.id AND is_deleted = FALSE) as message_count
            FROM users u
            WHERE u.id = %s
        """, (user_id,))
        
        user = c.fetchone()
        conn.close()
        
        if not user:
            return jsonify({'success': False, 'error': 'User not found'})
        
        profile_data = dict(user)
        
        # Format dates
        if profile_data['created_at']:
            profile_data['member_since'] = profile_data['created_at'].strftime('%Y-%m-%d')
        
        # Check ban status
        ban_info = check_ban_status(user_id)
        if ban_info:
            profile_data['banned'] = True
            profile_data['ban_reason'] = ban_info['reason']
            profile_data['ban_duration'] = ban_info['duration_text']
            profile_data['ban_expires'] = ban_info['expires_at'].isoformat() if ban_info['expires_at'] else None
        else:
            profile_data['banned'] = False
            profile_data['is_banned'] = False
        
        return jsonify({'success': True, 'profile': profile_data})
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/user/activity')
def user_activity():
    """Get user activity for heatmap"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'})
    
    user_id = session['user_id']
    days = request.args.get('days', 30, type=int)
    
    try:
        conn = get_db()
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        c.execute("""
            SELECT DATE(timestamp) as date, COUNT(*) as count
            FROM user_activity
            WHERE user_id = %s AND timestamp > NOW() - INTERVAL '%s days'
            GROUP BY DATE(timestamp)
            ORDER BY date
        """, (user_id, days))
        
        activity = c.fetchall()
        conn.close()
        
        return jsonify({
            'success': True, 
            'activity': [dict(row) for row in activity]
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/community/messages', methods=['GET', 'POST'])
def community_messages():
    """Handle community chat with ban enforcement"""
    if request.method == 'POST':
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not logged in'})
        
        user_id = session['user_id']
        
        # Check ban status
        ban_info = check_ban_status(user_id)
        if ban_info:
            return jsonify({
                'success': False, 
                'error': f'You are banned: {ban_info["reason"]}',
                'ban_info': ban_info,
                'banned': True
            })
        
        data = request.get_json()
        message = data.get('message', '').strip()
        category = data.get('category', 'general')
        
        if not message:
            return jsonify({'success': False, 'error': 'Message cannot be empty'})
        
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute("""
                INSERT INTO community_messages (user_id, message, category)
                VALUES (%s, %s, %s) RETURNING id
            """, (user_id, message, category))
            msg_id = c.fetchone()[0]
            conn.commit()
            conn.close()
            
            log_activity(user_id, 'community_message', {'category': category})
            
            return jsonify({
                'success': True, 
                'id': msg_id,
                'message': 'Message posted'
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    
    else:  # GET
        try:
            conn = get_db()
            c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            category = request.args.get('category')
            
            if category:
                c.execute("""
                    SELECT m.*, u.name, u.picture, u.role
                    FROM community_messages m
                    JOIN users u ON m.user_id = u.id
                    WHERE m.category = %s AND m.is_deleted = FALSE
                    ORDER BY m.timestamp DESC LIMIT 50
                """, (category,))
            else:
                c.execute("""
                    SELECT m.*, u.name, u.picture, u.role
                    FROM community_messages m
                    JOIN users u ON m.user_id = u.id
                    WHERE m.is_deleted = FALSE
                    ORDER BY m.timestamp DESC LIMIT 50
                """)
            
            messages = c.fetchall()
            conn.close()
            
            return jsonify({
                'success': True,
                'messages': [dict(m) for m in messages]
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

@app.route('/api/stats/most-liked')
def most_liked_verses():
    """Get most liked verses analytics"""
    try:
        conn = get_db()
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        c.execute("""
            SELECT v.id, v.reference, v.text,
                   COUNT(l.id) as like_count
            FROM verses v
            LEFT JOIN liked_verses l ON v.id = l.verse_id
            GROUP BY v.id
            ORDER BY like_count DESC
            LIMIT 10
        """)
        
        verses = c.fetchall()
        conn.close()
        
        return jsonify({
            'success': True,
            'verses': [dict(v) for v in verses]
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/auth/google', methods=['POST'])
def auth_google():
    """Handle Google OAuth"""
    try:
        data = request.get_json()
        token = data.get('token')
        
        # Verify with Google
        r = requests.get(f'https://oauth2.googleapis.com/tokeninfo?id_token={token}')
        user_info = r.json()
        
        if 'error' in user_info:
            return jsonify({'success': False, 'error': 'Invalid token'})
        
        email = user_info['email']
        name = user_info.get('name', email.split('@')[0])
        picture = user_info.get('picture', '')
        google_id = user_info['sub']
        
        conn = get_db()
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Check if user exists
        c.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = c.fetchone()
        
        if not user:
            c.execute("""
                INSERT INTO users (name, email, picture, google_id, role, created_at) 
                VALUES (%s, %s, %s, %s, 'user', NOW()) RETURNING id
            """, (name, email, picture, google_id))
            user_id = c.fetchone()['id']
            is_new = True
        else:
            user_id = user['id']
            is_new = False
            
            # Update picture if changed
            if picture and user.get('picture') != picture:
                c.execute("UPDATE users SET picture = %s WHERE id = %s", (picture, user_id))
            
            # Update last active
            c.execute("UPDATE users SET last_active = NOW() WHERE id = %s", (user_id,))
        
        conn.commit()
        conn.close()
        
        # Set session
        session['user_id'] = user_id
        session['email'] = email
        session['name'] = name
        
        return jsonify({
            'success': True, 
            'user': {
                'id': user_id, 
                'name': name, 
                'email': email,
                'picture': picture,
                'is_new': is_new
            }
        })
        
    except Exception as e:
        print(f"Auth error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/logout')
def logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/api/check-ban')
def check_ban():
    """Endpoint to check if current user is banned"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'})
    
    user_id = session['user_id']
    ban_info = check_ban_status(user_id)
    
    if ban_info:
        return jsonify({
            'success': True,
            'banned': True,
            'ban_info': ban_info
        })
    else:
        return jsonify({
            'success': True,
            'banned': False
        })

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
