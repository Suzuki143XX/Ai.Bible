
admin_code = '''from flask import Flask, render_template, jsonify, request, redirect, url_for, session, flash
import subprocess
import sys
import os
import random
import string

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    print("Installing psycopg2-binary...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "psycopg2-binary"])
    import psycopg2
    import psycopg2.extras

from datetime import datetime, timedelta
from functools import wraps
import json

app = Flask(__name__)
app.secret_key = 'local-admin-dashboard-secret-key-v2'

# Database connection - Using your actual Render database
DATABASE_URL = "postgresql://bible_db_2y32_user:aw2y7YQyqKZTPLCPaUcOs5wybLEJpqQX@dpg-d67hk9ggjchc73amsghg-a.oregon-postgres.render.com/bible_db_2y32"

# Role hierarchy (higher number = more power)
ROLES = {
    'user': 0,
    'host': 1,        # Temp ban only (1hr - 1 month)
    'mod': 2,         # Temp ban + delete content
    'contributor': 3, # Perm ban/unban + delete
    'co_owner': 4,    # Almost everything + demote lower roles
    'owner': 5        # Everything + role management
}

ROLE_INFO = {
    'user': {'color': '#718096', 'label': 'User', 'icon': '👤'},
    'host': {'color': '#38a169', 'label': 'Host', 'icon': '🎤'},
    'mod': {'color': '#3182ce', 'label': 'Moderator', 'icon': '🛡️'},
    'contributor': {'color': '#805ad5', 'label': 'Contributor', 'icon': '⭐'},
    'co_owner': {'color': '#dd6b20', 'label': 'Co-Owner', 'icon': '👑'},
    'owner': {'color': '#e53e3e', 'label': 'Owner', 'icon': '🔥'}
}

ROLE_COLORS = {
    'user': '#718096',
    'host': '#38a169',
    'mod': '#3182ce',
    'contributor': '#805ad5',
    'co_owner': '#dd6b20',
    'owner': '#e53e3e'
}

MASTER_PASSWORD = "God Is All"

# Passcode file path
PASSCODE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'passcodes.txt')

def generate_passcode():
    """Generate random passcode format: XXXX-XXXX-XXXX"""
    parts = []
    for _ in range(3):
        parts.append(''.join(random.choices(string.ascii_uppercase + string.digits, k=4)))
    return '-'.join(parts)

def init_passcodes():
    """Create passcodes.txt if it doesn't exist"""
    if not os.path.exists(PASSCODE_FILE):
        codes = {
            'HOST': f"HOST-{generate_passcode()}",
            'MOD': f"MOD-{generate_passcode()}",
            'CONTRIBUTOR': f"CONTRIB-{generate_passcode()}",
            'CO_OWNER': f"COOWNER-{generate_passcode()}",
            'OWNER': "Gmelchor2001@@"
        }
        with open(PASSCODE_FILE, 'w') as f:
            f.write("# Bible AI Admin Passcodes\\n")
            f.write("# Format: ROLE: CODE\\n")
            f.write("# Owner code is fixed, others can be changed\\n\\n")
            for role, code in codes.items():
                f.write(f"{role}: {code}\\n")
        print(f"✓ Generated passcodes file: {PASSCODE_FILE}")
        return codes
    else:
        codes = {}
        with open(PASSCODE_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and ':' in line:
                    role, code = line.split(':', 1)
                    codes[role.strip()] = code.strip()
        return codes

PASSCODES = init_passcodes()

def get_db():
    return psycopg2.connect(DATABASE_URL, sslmode='require')

def init_db():
    """Initialize database columns if they don't exist"""
    conn = None
    try:
        conn = get_db()
        c = conn.cursor()
        
        # Check and add role column
        c.execute("""
            SELECT column_name FROM information_schema.columns 
            WHERE table_name='users' AND column_name='role'
        """)
        if not c.fetchone():
            c.execute("ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT 'user'")
            print("Added 'role' column")
        
        # Check and add is_banned column
        c.execute("""
            SELECT column_name FROM information_schema.columns 
            WHERE table_name='users' AND column_name='is_banned'
        """)
        if not c.fetchone():
            c.execute("ALTER TABLE users ADD COLUMN is_banned BOOLEAN DEFAULT FALSE")
            print("Added 'is_banned' column")
        
        # Check and add ban_expires_at column
        c.execute("""
            SELECT column_name FROM information_schema.columns 
            WHERE table_name='users' AND column_name='ban_expires_at'
        """)
        if not c.fetchone():
            c.execute("ALTER TABLE users ADD COLUMN ban_expires_at TIMESTAMP")
            print("Added 'ban_expires_at' column")
        
        # Check and add ban_reason column
        c.execute("""
            SELECT column_name FROM information_schema.columns 
            WHERE table_name='users' AND column_name='ban_reason'
        """)
        if not c.fetchone():
            c.execute("ALTER TABLE users ADD COLUMN ban_reason TEXT")
            print("Added 'ban_reason' column")
        
        # Create audit_logs table if not exists
        c.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id SERIAL PRIMARY KEY,
                admin_id INTEGER REFERENCES users(id),
                action VARCHAR(50),
                target_user_id INTEGER REFERENCES users(id),
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        print("✓ Database initialized")
    except Exception as e:
        print(f"Init error: {e}")
    finally:
        if conn:
            conn.close()

def has_permission(min_role):
    """Check if current user has required role level"""
    if not session.get('admin_logged_in'):
        return False
    current_role = session.get('admin_role', 'user')
    return ROLES.get(current_role, 0) >= ROLES.get(min_role, 0)

def require_role(min_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('admin_logged_in'):
                return redirect(url_for('login'))
            if not has_permission(min_role):
                flash(f'You need {min_role} permissions to access this.', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def log_action(action, target_user_id=None, details=None):
    """Log admin actions"""
    conn = None
    try:
        conn = get_db()
        c = conn.cursor()
        admin_id = session.get('admin_user_id')
        c.execute("""
            INSERT INTO audit_logs (admin_id, action, target_user_id, details)
            VALUES (%s, %s, %s, %s)
        """, (admin_id, action, target_user_id, json.dumps(details) if details else None))
        conn.commit()
    except Exception as e:
        print(f"Log action error: {e}")
    finally:
        if conn:
            conn.close()

@app.route('/')
def index():
    if not session.get('admin_logged_in'):
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Simple login: Enter email + password. Auto-grants Host if no role set."""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        if not email or not password:
            return render_template('admin_login.html', error='Please enter email and password')
        
        conn = None
        try:
            conn = get_db()
            c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            c.execute("SELECT * FROM users WHERE LOWER(email) = %s", (email,))
            user = c.fetchone()
            
            if not user:
                return render_template('admin_login.html', error='Email not found in database')
            
            if password == MASTER_PASSWORD:
                session['admin_logged_in'] = True
                session['admin_user_id'] = user['id']
                session['admin_name'] = user['name']
                session['admin_email'] = user['email']
                
                # Check if user has role column and set default if needed
                user_role = user.get('role', 'user')
                if not user_role or user_role == 'user':
                    c.execute("UPDATE users SET role = 'host' WHERE id = %s", (user['id'],))
                    conn.commit()
                    session['admin_role'] = 'host'
                    flash('Welcome! You have been granted Host permissions.', 'success')
                else:
                    session['admin_role'] = user_role
                
                log_action('login')
                return redirect(url_for('dashboard'))
            else:
                return render_template('admin_login.html', error='Invalid password')
        except Exception as e:
            print(f"Login error: {e}")
            return render_template('admin_login.html', error='Database error')
        finally:
            if conn:
                conn.close()
    
    return render_template('admin_login.html')

@app.route('/claim-role', methods=['POST'])
@require_role('user')
def claim_role():
    """Claim a role using passcode"""
    data = request.get_json()
    role = data.get('role', '').lower()
    code = data.get('code', '').strip()
    
    if not role or not code:
        return jsonify({'success': False, 'error': 'Missing role or code'})
    
    if role not in ROLES or role == 'user':
        return jsonify({'success': False, 'error': 'Invalid role'})
    
    current_role = session.get('admin_role', 'user')
    if ROLES.get(current_role, 0) >= ROLES.get(role, 0):
        return jsonify({'success': False, 'error': f'You already have {current_role} or higher'})
    
    expected_code = PASSCODES.get(role.upper())
    if not expected_code or code != expected_code:
        return jsonify({'success': False, 'error': 'Invalid passcode'})
    
    conn = None
    try:
        conn = get_db()
        c = conn.cursor()
        user_id = session.get('admin_user_id')
        
        c.execute("UPDATE users SET role = %s WHERE id = %s", (role, user_id))
        conn.commit()
        
        session['admin_role'] = role
        
        log_action('role_claimed', details={'new_role': role, 'old_role': current_role})
        
        return jsonify({
            'success': True, 
            'message': f'Successfully claimed {ROLE_INFO.get(role, {}).get("label", role)} role!'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
    finally:
        if conn:
            conn.close()

@app.route('/dashboard')
@require_role('host')
def dashboard():
    conn = None
    try:
        conn = get_db()
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        stats = {}
        
        # Total users
        c.execute("SELECT COUNT(*) as count FROM users")
        result = c.fetchone()
        stats['total_users'] = result['count'] if result else 0
        
        # Active bans - check if expired
        c.execute("""
            SELECT COUNT(*) as count FROM users 
            WHERE is_banned = TRUE 
            AND (ban_expires_at IS NULL OR ban_expires_at > NOW())
        """)
        result = c.fetchone()
        stats['active_bans'] = result['count'] if result else 0
        
        # Comments in 24h
        c.execute("""
            SELECT COUNT(*) as count FROM comments 
            WHERE timestamp::timestamp > NOW() - INTERVAL '24 hours'
        """)
        result = c.fetchone()
        stats['comments_24h'] = result['count'] if result else 0
        
        # Messages in 24h
        c.execute("""
            SELECT COUNT(*) as count FROM community_messages 
            WHERE timestamp::timestamp > NOW() - INTERVAL '24 hours'
        """)
        result = c.fetchone()
        stats['messages_24h'] = result['count'] if result else 0
        
        # Recent users with counts
        c.execute("""
            SELECT u.id, u.name, u.email, u.picture, u.role, u.is_banned, 
                   u.created_at::timestamp as created_at,
                   COUNT(DISTINCT c.id) as comment_count,
                   COUNT(DISTINCT m.id) as message_count
            FROM users u
            LEFT JOIN comments c ON u.id = c.user_id
            LEFT JOIN community_messages m ON u.id = m.user_id
            GROUP BY u.id
            ORDER BY u.created_at::timestamp DESC
            LIMIT 10
        """)
        recent_users = c.fetchall()
        
        # Recent audit logs
        c.execute("""
            SELECT a.id, a.action, a.target_user_id, a.details,
                   a.created_at::timestamp as created_at,
                   admin.name as admin_name, target.name as target_name
            FROM audit_logs a
            JOIN users admin ON a.admin_id = admin.id
            LEFT JOIN users target ON a.target_user_id = target.id
            ORDER BY a.created_at DESC
            LIMIT 20
        """)
        recent_logs = c.fetchall()
        
        return render_template('admin_dashboard.html',
                             stats=stats,
                             recent_users=recent_users,
                             recent_logs=recent_logs,
                             ROLE_INFO=ROLE_INFO,
                             ROLE_COLORS=ROLE_COLORS,
                             current_role=session.get('admin_role'),
                             has_permission=has_permission,
                             passcodes=PASSCODES)
    except Exception as e:
        flash(f'Error loading dashboard: {e}', 'error')
        return redirect(url_for('login'))
    finally:
        if conn:
            conn.close()

@app.route('/users')
@require_role('host')
def users():
    conn = None
    try:
        conn = get_db()
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        search = request.args.get('search', '')
        role_filter = request.args.get('role', '')
        banned_only = request.args.get('banned', '')
        
        query = """
            SELECT u.id, u.name, u.email, u.picture, u.role, u.is_banned, 
                   u.ban_expires_at::timestamp as ban_expires_at,
                   u.ban_reason, u.created_at::timestamp as created_at,
                   COUNT(DISTINCT c.id) as comment_count,
                   COUNT(DISTINCT m.id) as message_count
            FROM users u
            LEFT JOIN comments c ON u.id = c.user_id
            LEFT JOIN community_messages m ON u.id = m.user_id
            WHERE 1=1
        """
        params = []
        
        if search:
            query += " AND (u.name ILIKE %s OR u.email ILIKE %s)"
            params.extend([f'%{search}%', f'%{search}%'])
        
        if role_filter:
            query += " AND u.role = %s"
            params.append(role_filter)
        
        if banned_only:
            query += " AND u.is_banned = TRUE"
        
        query += " GROUP BY u.id ORDER BY u.created_at::timestamp DESC LIMIT 100"
        
        c.execute(query, params)
        users = c.fetchall()
        
        c.execute("SELECT DISTINCT role FROM users ORDER BY role")
        roles = [r['role'] for r in c.fetchall() if r['role']]
        
        return render_template('admin_users.html',
                             users=users,
                             roles=roles,
                             ROLE_INFO=ROLE_INFO,
                             ROLE_COLORS=ROLE_COLORS,
                             current_role=session.get('admin_role'),
                             has_permission=has_permission)
    except Exception as e:
        flash(f'Error loading users: {e}', 'error')
        return redirect(url_for('dashboard'))
    finally:
        if conn:
            conn.close()

@app.route('/user/<int:user_id>')
@require_role('host')
def user_detail(user_id):
    conn = None
    try:
        conn = get_db()
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Get user with proper typing
        c.execute("""
            SELECT u.*, u.created_at::timestamp as created_at,
                   u.ban_expires_at::timestamp as ban_expires_at
            FROM users u WHERE u.id = %s
        """, (user_id,))
        user = c.fetchone()
        
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('users'))
        
        # Convert boolean properly
        if 'is_banned' in user:
            user['is_banned'] = bool(user['is_banned'])
        
        # Get current user's role level
        current_user_id = session.get('admin_user_id')
        current_role = session.get('admin_role', 'user')
        current_level = ROLES.get(current_role, 0)
        target_level = ROLES.get(user.get('role', 'user'), 0)
        
        # Determine if current user can manage this target
        can_ban = False
        can_change_role = False
        
        # Cannot ban yourself
        if user['id'] != current_user_id:
            # Owners cannot be banned by anyone
            if user.get('role') != 'owner':
                can_ban = has_permission('host')
            
            # Role management permissions
            if has_permission('owner'):
                can_change_role = True
            elif has_permission('co_owner') and target_level < ROLES['co_owner']:
                can_change_role = True
        
        # Get user's comments with verse references
        c.execute("""
            SELECT c.*, c.timestamp::timestamp as timestamp, v.reference 
            FROM comments c
            LEFT JOIN verses v ON c.verse_id = v.id
            WHERE c.user_id = %s
            ORDER BY c.timestamp::timestamp DESC
            LIMIT 50
        """, (user_id,))
        comments = c.fetchall()
        
        # Get user's messages
        c.execute("""
            SELECT *, timestamp::timestamp as timestamp 
            FROM community_messages 
            WHERE user_id = %s
            ORDER BY timestamp::timestamp DESC
            LIMIT 50
        """, (user_id,))
        messages = c.fetchall()
        
        # Get ban history
        c.execute("""
            SELECT a.*, a.created_at::timestamp as created_at, admin.name as admin_name
            FROM audit_logs a
            JOIN users admin ON a.admin_id = admin.id
            WHERE a.target_user_id = %s AND a.action IN ('ban', 'unban', 'temp_ban')
            ORDER BY a.created_at DESC
        """, (user_id,))
        ban_history = c.fetchall()
        
        return render_template('admin_user_detail.html',
                             user=user,
                             comments=comments,
                             messages=messages,
                             ban_history=ban_history,
                             ROLE_INFO=ROLE_INFO,
                             ROLE_COLORS=ROLE_COLORS,
                             has_permission=has_permission,
                             can_ban=can_ban,
                             can_change_role=can_change_role)
    except Exception as e:
        flash(f'Error loading user: {e}', 'error')
        return redirect(url_for('users'))
    finally:
        if conn:
            conn.close()

@app.route('/content')
@require_role('mod')
def content_moderation():
    conn = None
    try:
        conn = get_db()
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        c.execute("""
            SELECT c.*, c.timestamp::timestamp as timestamp, u.name, u.role, u.is_banned, v.reference
            FROM comments c
            JOIN users u ON c.user_id = u.id
            LEFT JOIN verses v ON c.verse_id = v.id
            ORDER BY c.timestamp::timestamp DESC
            LIMIT 50
        """)
        comments = c.fetchall()
        
        c.execute("""
            SELECT m.*, m.timestamp::timestamp as timestamp, u.name, u.role, u.is_banned
            FROM community_messages m
            JOIN users u ON m.user_id = u.id
            ORDER BY m.timestamp::timestamp DESC
            LIMIT 50
        """)
        messages = c.fetchall()
        
        return render_template('admin_content.html',
                             comments=comments,
                             messages=messages,
                             ROLE_INFO=ROLE_INFO,
                             ROLE_COLORS=ROLE_COLORS,
                             current_role=session.get('admin_role'),
                             has_permission=has_permission)
    except Exception as e:
        flash(f'Error loading content: {e}', 'error')
        return redirect(url_for('dashboard'))
    finally:
        if conn:
            conn.close()

@app.route('/audit-log')
@require_role('co_owner')
def audit_log():
    conn = None
    try:
        conn = get_db()
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        c.execute("""
            SELECT a.*, a.created_at::timestamp as created_at, 
                   admin.name as admin_name, target.name as target_name
            FROM audit_logs a
            JOIN users admin ON a.admin_id = admin.id
            LEFT JOIN users target ON a.target_user_id = target.id
            ORDER BY a.created_at DESC
            LIMIT 100
        """)
        logs = c.fetchall()
        
        return render_template('admin_audit.html', 
                             logs=logs,
                             ROLE_INFO=ROLE_INFO,
                             ROLE_COLORS=ROLE_COLORS,
                             current_role=session.get('admin_role'),
                             has_permission=has_permission)
    except Exception as e:
        flash(f'Error loading audit log: {e}', 'error')
        return redirect(url_for('dashboard'))
    finally:
        if conn:
            conn.close()

@app.route('/api/ban_user', methods=['POST'])
@require_role('host')
def ban_user():
    """Fixed ban endpoint with comprehensive error handling"""
    conn = None
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No JSON data received'}), 400
        
        user_id = data.get('user_id')
        duration = data.get('duration')
        reason = data.get('reason', '').strip()
        
        # Validation
        if not user_id:
            return jsonify({'success': False, 'error': 'User ID is required'}), 400
        
        if not duration:
            return jsonify({'success': False, 'error': 'Duration is required'}), 400
        
        # Convert user_id to int safely
        try:
            user_id = int(user_id)
        except (ValueError, TypeError):
            return jsonify({'success': False, 'error': f'Invalid user ID format: {user_id}'}), 400
        
        current_user_id = session.get('admin_user_id')
        if not current_user_id:
            return jsonify({'success': False, 'error': 'Not logged in'}), 401
        
        current_user_id = int(current_user_id)
        
        # Cannot ban yourself
        if user_id == current_user_id:
            return jsonify({'success': False, 'error': 'You cannot ban yourself'}), 403
        
        conn = get_db()
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Get target user with lock to prevent race conditions
        c.execute("SELECT id, role, is_banned, email, name FROM users WHERE id = %s FOR UPDATE", (user_id,))
        target = c.fetchone()
        
        if not target:
            return jsonify({'success': False, 'error': f'User with ID {user_id} not found'}), 404
        
        # Check if already banned
        if target.get('is_banned'):
            return jsonify({'success': False, 'error': f'User {target[\"name\"]} is already banned'}), 400
        
        # Owners cannot be banned by anyone
        if target.get('role') == 'owner':
            return jsonify({'success': False, 'error': 'Owners cannot be banned'}), 403
        
        # Permission check for permanent ban
        if duration == 'permanent' and not has_permission('contributor'):
            return jsonify({'success': False, 'error': 'Only Contributors+ can ban permanently'}), 403
        
        # Calculate expiration
        expires_at = None
        if duration == '1hour':
            expires_at = datetime.now() + timedelta(hours=1)
        elif duration == '1day':
            expires_at = datetime.now() + timedelta(days=1)
        elif duration == '1week':
            expires_at = datetime.now() + timedelta(weeks=1)
        elif duration == '1month':
            expires_at = datetime.now() + timedelta(days=30)
        elif duration == 'permanent':
            expires_at = None
        else:
            return jsonify({'success': False, 'error': f'Invalid duration: {duration}'}), 400
        
        # Update user ban status
        c.execute("""
            UPDATE users 
            SET is_banned = TRUE, 
                ban_expires_at = %s,
                ban_reason = %s
            WHERE id = %s
            RETURNING id, name, email
        """, (expires_at, reason if reason else None, user_id))
        
        result = c.fetchone()
        conn.commit()
        
        if not result:
            return jsonify({'success': False, 'error': 'Database update failed - no rows affected'}), 500
        
        # Log the action
        action = 'temp_ban' if expires_at else 'ban'
        log_action(action, user_id, {
            'duration': duration, 
            'reason': reason,
            'expires_at': expires_at.isoformat() if expires_at else None,
            'target_name': target['name'],
            'target_email': target['email']
        })
        
        return jsonify({
            'success': True, 
            'message': f"User {target['name']} has been successfully banned",
            'user_id': user_id,
            'duration': duration,
            'expires_at': expires_at.isoformat() if expires_at else None,
            'is_permanent': duration == 'permanent'
        })
        
    except Exception as e:
        import traceback
        error_msg = f"Ban error: {str(e)}\\n{traceback.format_exc()}"
        print(error_msg)
        return jsonify({'success': False, 'error': f'Server error: {str(e)}'}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/unban_user/<int:user_id>', methods=['POST'])
@require_role('contributor')
def unban_user(user_id):
    """Fixed unban endpoint"""
    conn = None
    try:
        current_user_id = session.get('admin_user_id')
        
        if not current_user_id:
            return jsonify({'success': False, 'error': 'Not logged in'}), 401
        
        current_user_id = int(current_user_id)
        
        # Cannot unban yourself
        if user_id == current_user_id:
            return jsonify({'success': False, 'error': 'Invalid action'}), 400
        
        conn = get_db()
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Get user info before unbanning
        c.execute("SELECT id, name, email, is_banned FROM users WHERE id = %s", (user_id,))
        user = c.fetchone()
        
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
            
        if not user.get('is_banned'):
            return jsonify({'success': False, 'error': 'User is not currently banned'}), 400
        
        c.execute("""
            UPDATE users 
            SET is_banned = FALSE, 
                ban_expires_at = NULL,
                ban_reason = NULL
            WHERE id = %s
            RETURNING id
        """, (user_id,))
        
        result = c.fetchone()
        conn.commit()
        
        if not result:
            return jsonify({'success': False, 'error': 'Failed to unban user'}), 500
        
        log_action('unban', user_id, {
            'target_name': user['name'],
            'target_email': user['email']
        })
        
        return jsonify({
            'success': True, 
            'message': f"User {user['name']} has been unbanned",
            'user_id': user_id
        })
        
    except Exception as e:
        import traceback
        print(f"Unban error: {str(e)}\\n{traceback.format_exc()}")
        return jsonify({'success': False, 'error': f'Server error: {str(e)}'}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/change_role', methods=['POST'])
@require_role('host')
def change_role():
    conn = None
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        new_role = data.get('role')
        
        if not user_id or not new_role:
            return jsonify({'success': False, 'error': 'Missing parameters'}), 400
        
        if new_role not in ROLES:
            return jsonify({'success': False, 'error': 'Invalid role'}), 400
        
        current_user_id = session.get('admin_user_id')
        current_role = session.get('admin_role', 'user')
        current_level = ROLES.get(current_role, 0)
        new_level = ROLES.get(new_role, 0)
        
        # Cannot change your own role
        if int(user_id) == int(current_user_id):
            return jsonify({'success': False, 'error': 'You cannot change your own role'}), 403
        
        conn = get_db()
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        c.execute("SELECT role FROM users WHERE id = %s", (user_id,))
        target = c.fetchone()
        
        if not target:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        target_current_role = target['role']
        target_level = ROLES.get(target_current_role, 0)
        
        # Hierarchy enforcement
        if not has_permission('co_owner'):
            return jsonify({'success': False, 'error': 'Only Co-Owners and above can change roles'}), 403
        
        # Co-owners cannot modify owners or other co-owners
        if has_permission('co_owner') and not has_permission('owner'):
            if target_level >= ROLES['co_owner']:
                return jsonify({'success': False, 'error': 'Co-Owners cannot modify Owners or other Co-Owners'}), 403
            if new_level >= ROLES['co_owner']:
                return jsonify({'success': False, 'error': 'Co-Owners can only assign roles up to Contributor'}), 403
        
        c.execute("UPDATE users SET role = %s WHERE id = %s", (new_role, user_id))
        conn.commit()
        
        log_action('role_change', user_id, {
            'new_role': new_role, 
            'old_role': target_current_role,
            'changed_by': current_role
        })
        return jsonify({'success': True, 'message': f'Role changed to {new_role}'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/delete_content', methods=['DELETE'])
@require_role('mod')
def delete_content():
    conn = None
    try:
        content_type = request.args.get('type')
        content_id = request.args.get('id')
        
        if not content_type or not content_id:
            return jsonify({'success': False, 'error': 'Missing type or id'}), 400
        
        conn = get_db()
        c = conn.cursor()
        
        if content_type == 'comment':
            c.execute("DELETE FROM comments WHERE id = %s", (content_id,))
        elif content_type == 'message':
            c.execute("DELETE FROM community_messages WHERE id = %s", (content_id,))
        else:
            return jsonify({'success': False, 'error': 'Invalid content type'}), 400
        
        conn.commit()
        
        log_action(f'delete_{content_type}', details={'content_id': content_id})
        return jsonify({'success': True, 'message': 'Content deleted'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    
    # Get local IP for iPhone access
    import socket
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    
    print("="*60)
    print("BIBLE AI - LOCAL ADMIN DASHBOARD (FIXED)")
    print("="*60)
    print(f"LOCAL:   http://localhost:5001")
    print(f"NETWORK: http://{local_ip}:5001  <-- Use this on iPhone")
    print(f"PASSWORD: {MASTER_PASSWORD}")
    print("="*60)
    
    # Run on 0.0.0.0 to allow iPhone access
    app.run(host='0.0.0.0', port=5001, debug=True)
'''

with open('/mnt/kimi/output/admin_fixed.py', 'w') as f:
    f.write(admin_code)

print("✅ Fixed admin.py saved")
print("\nKey fixes in admin.py:")
print("- Added proper try-except-finally blocks around ALL database operations")
print("- Added FOR UPDATE lock when fetching user to ban (prevents race conditions)")
print("- Added RETURNING clause to verify updates actually happened")
print("- Added validation for already banned users")
print("- Better error messages with specific HTTP status codes")
print("- Connection cleanup in finally blocks prevents connection leaks")
