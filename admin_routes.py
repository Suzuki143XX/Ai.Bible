"""
Admin Extension for Bible AI App - FIXED for old databases
"""

from flask import Blueprint, render_template, jsonify, request, session, redirect, url_for, flash
from functools import wraps
from datetime import datetime, timedelta
import json
import logging
from app import get_db, get_cursor, ADMIN_CODE, MASTER_PASSWORD, IS_POSTGRES, HAS_BAN_COLUMNS, check_column_exists_app as app_check_column, log_action

logger = logging.getLogger(__name__)

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('admin.admin_login'))
        if not session.get('is_admin'):
            return redirect(url_for('admin.admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def safe_get(row, keys, default=None):
    """Safely get value from row (dict or tuple) with fallback"""
    if isinstance(row, dict):
        for key in keys:
            if key in row:
                return row[key]
        return default
    else:
        # It's a tuple, try indices
        index_map = {'id': 0, 'google_id': 1, 'email': 2, 'name': 3, 'picture': 4, 
                     'created_at': 5, 'is_admin': 6}
        for key in keys:
            if key in index_map and index_map[key] < len(row):
                return row[index_map[key]]
        return default

def check_column_exists(conn, db_type, table, column):
    """Check if a column exists in the table"""
    try:
        c = get_cursor(conn, db_type)
        if db_type == 'postgres':
            c.execute("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = %s AND column_name = %s
            """, (table, column))
            result = c.fetchone()
            return result is not None
        else:
            c.execute(f"PRAGMA table_info({table})")
            columns = [col[1] for col in c.fetchall()]
            return column in columns
    except Exception as e:
        logger.error(f"Column check error: {e}")
        return False

# ============ ADMIN AUTH ============

@admin_bp.route('/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        password = data.get('password', '')
        user_id = data.get('user_id') or session.get('user_id')
        
        if password == MASTER_PASSWORD:
            if user_id:
                session['user_id'] = int(user_id)
                session['is_admin'] = True
                session['role'] = 'host'
                return jsonify({"success": True, "redirect": "/admin/dashboard"})
            return jsonify({"success": False, "error": "No user selected"})
        
        return jsonify({"success": False, "error": "Invalid master password"})
    
    return render_template('admin_login.html')

@admin_bp.route('/logout')
def admin_logout():
    session.pop('is_admin', None)
    session.pop('role', None)
    return redirect(url_for('admin.admin_login'))

# ============ DASHBOARD ============

@admin_bp.route('/')
@admin_bp.route('/dashboard')
@admin_required
def admin_dashboard():
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    stats = {}
    try:
        # Basic stats that always work
        c.execute("SELECT COUNT(*) as count FROM users")
        result = c.fetchone()
        stats['total_users'] = result['count'] if isinstance(result, dict) else result[0]
        
        c.execute("SELECT COUNT(*) as count FROM verses")
        result = c.fetchone()
        stats['total_verses'] = result['count'] if isinstance(result, dict) else result[0]
        
        c.execute("SELECT COUNT(*) as count FROM likes")
        result = c.fetchone()
        stats['total_likes'] = result['count'] if isinstance(result, dict) else result[0]
        
        c.execute("SELECT COUNT(*) as count FROM saves")
        result = c.fetchone()
        stats['total_saves'] = result['count'] if isinstance(result, dict) else result[0]
        
        # Check if is_banned exists
        has_banned = check_column_exists(conn, db_type, 'users', 'is_banned')
        
        if has_banned:
            if db_type == 'postgres':
                c.execute("SELECT COUNT(*) as count FROM users WHERE is_banned = TRUE")
            else:
                c.execute("SELECT COUNT(*) as count FROM users WHERE is_banned = 1")
            result = c.fetchone()
            stats['banned_users'] = result['count'] if isinstance(result, dict) else result[0]
        else:
            stats['banned_users'] = 0
        
        # Recent users
        c.execute("SELECT id, name, email, created_at FROM users ORDER BY created_at DESC LIMIT 5")
        recent_users = []
        for row in c.fetchall():
            if isinstance(row, dict):
                recent_users.append({
                    'name': row.get('name', 'Unknown'),
                    'email': row.get('email', ''),
                    'created_at': row.get('created_at', ''),
                    'is_banned': row.get('is_banned', False) if has_banned else False
                })
            else:
                recent_users.append({
                    'name': row[3] if len(row) > 3 else 'Unknown',
                    'email': row[2] if len(row) > 2 else '',
                    'created_at': row[5] if len(row) > 5 else '',
                    'is_banned': False
                })
        
        # Check if audit_logs exists
        has_audit = check_column_exists(conn, db_type, 'audit_logs', 'id')
        recent_audit = []
        
        if has_audit:
            try:
                c.execute("""
                    SELECT a.*, u.name as admin_name 
                    FROM audit_logs a 
                    LEFT JOIN users u ON a.admin_id = u.id 
                    ORDER BY a.created_at DESC 
                    LIMIT 10
                """)
                for row in c.fetchall():
                    if isinstance(row, dict):
                        recent_audit.append({
                            'action': row.get('action', ''),
                            'admin_name': row.get('admin_name', 'System'),
                            'created_at': row.get('created_at', '')
                        })
            except:
                pass
        
        return render_template('admin_dashboard.html', 
                             stats=stats, 
                             recent_users=recent_users, 
                             recent_audit=recent_audit,
                             db_type=db_type)
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return f"Error: {str(e)}", 500
    finally:
        conn.close()

# ============ USERS ============

@admin_bp.route('/users')
@admin_required
def admin_users():
    return render_template('admin_users.html')

@admin_bp.route('/api/users')
@admin_required
def api_users():
    search = request.args.get('search', '')
    status = request.args.get('status', 'all')
    sort = request.args.get('sort', 'newest')
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        has_banned = check_column_exists(conn, db_type, 'users', 'is_banned')
        has_role = check_column_exists(conn, db_type, 'users', 'role')
        
        query = "SELECT * FROM users WHERE 1=1"
        params = []
        
        if search:
            if db_type == 'postgres':
                query += " AND (name ILIKE %s OR email ILIKE %s)"
            else:
                query += " AND (name LIKE ? OR email LIKE ?)"
            params.extend([f'%{search}%', f'%{search}%'])
        
        if status == 'banned' and has_banned:
            query += " AND is_banned = TRUE" if db_type == 'postgres' else " AND is_banned = 1"
        elif status == 'admin':
            query += " AND is_admin = 1"
        
        if sort == 'newest':
            query += " ORDER BY created_at DESC"
        elif sort == 'oldest':
            query += " ORDER BY created_at ASC"
        elif sort == 'name':
            query += " ORDER BY name ASC"
        
        c.execute(query, params)
        
        rows = c.fetchall()
        users = []
        
        for row in rows:
            if isinstance(row, dict):
                user = {
                    "id": row.get('id'),
                    "name": row.get('name', 'Unknown'),
                    "email": row.get('email', ''),
                    "picture": row.get('picture', ''),
                    "created_at": row.get('created_at', ''),
                    "is_admin": bool(row.get('is_admin', 0)),
                    "is_banned": bool(row.get('is_banned', 0)) if has_banned else False,
                    "ban_reason": row.get('ban_reason', '') if has_banned else '',
                    "role": row.get('role', 'user') if has_role else ('admin' if row.get('is_admin') else 'user')
                }
            else:
                user = {
                    "id": row[0],
                    "name": row[3] if len(row) > 3 else 'Unknown',
                    "email": row[2] if len(row) > 2 else '',
                    "picture": row[4] if len(row) > 4 else '',
                    "created_at": row[5] if len(row) > 5 else '',
                    "is_admin": bool(row[6]) if len(row) > 6 else False,
                    "is_banned": False,
                    "ban_reason": '',
                    "role": 'admin' if (len(row) > 6 and row[6]) else 'user'
                }
            
            # Get stats
            try:
                if db_type == 'postgres':
                    c.execute("SELECT COUNT(*) FROM likes WHERE user_id = %s", (user['id'],))
                    result = c.fetchone()
                    user['likes_count'] = result['count'] if isinstance(result, dict) else result[0]
                    
                    c.execute("SELECT COUNT(*) FROM saves WHERE user_id = %s", (user['id'],))
                    result = c.fetchone()
                    user['saves_count'] = result['count'] if isinstance(result, dict) else result[0]
                    
                    c.execute("SELECT COUNT(*) FROM comments WHERE user_id = %s", (user['id'],))
                    result = c.fetchone()
                    user['comments_count'] = result['count'] if isinstance(result, dict) else result[0]
                else:
                    c.execute("SELECT COUNT(*) FROM likes WHERE user_id = ?", (user['id'],))
                    user['likes_count'] = c.fetchone()[0]
                    c.execute("SELECT COUNT(*) FROM saves WHERE user_id = ?", (user['id'],))
                    user['saves_count'] = c.fetchone()[0]
                    c.execute("SELECT COUNT(*) FROM comments WHERE user_id = ?", (user['id'],))
                    user['comments_count'] = c.fetchone()[0]
            except:
                user['likes_count'] = 0
                user['saves_count'] = 0
                user['comments_count'] = 0
            
            users.append(user)
        
        return jsonify({"users": users, "count": len(users)})
    except Exception as e:
        logger.error(f"API users error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@admin_bp.route('/user/<int:user_id>')
@admin_required
def admin_user_details(user_id):
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        if db_type == 'postgres':
            c.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        else:
            c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        
        row = c.fetchone()
        if not row:
            return "User not found", 404
        
        has_banned = check_column_exists(conn, db_type, 'users', 'is_banned')
        has_role = check_column_exists(conn, db_type, 'users', 'role')
        
        if isinstance(row, dict):
            user = {
                "id": row.get('id'),
                "google_id": row.get('google_id', ''),
                "name": row.get('name', 'Unknown'),
                "email": row.get('email', ''),
                "picture": row.get('picture', ''),
                "created_at": row.get('created_at', ''),
                "is_admin": bool(row.get('is_admin', 0)),
                "is_banned": bool(row.get('is_banned', 0)) if has_banned else False,
                "ban_reason": row.get('ban_reason', '') if has_banned else '',
                "ban_expires_at": row.get('ban_expires_at', '') if has_banned else '',
                "role": row.get('role', 'user') if has_role else ('admin' if row.get('is_admin') else 'user')
            }
        else:
            user = {
                "id": row[0],
                "google_id": row[1] if len(row) > 1 else '',
                "name": row[3] if len(row) > 3 else 'Unknown',
                "email": row[2] if len(row) > 2 else '',
                "picture": row[4] if len(row) > 4 else '',
                "created_at": row[5] if len(row) > 5 else '',
                "is_admin": bool(row[6]) if len(row) > 6 else False,
                "is_banned": False,
                "ban_reason": '',
                "ban_expires_at": '',
                "role": 'admin' if (len(row) > 6 and row[6]) else 'user'
            }
        
        # Get activity
        try:
            if db_type == 'postgres':
                c.execute("""
                    SELECT v.reference, v.text, l.timestamp 
                    FROM likes l 
                    JOIN verses v ON l.verse_id = v.id 
                    WHERE l.user_id = %s 
                    ORDER BY l.timestamp DESC
                """, (user_id,))
            else:
                c.execute("""
                    SELECT v.reference, v.text, l.timestamp 
                    FROM likes l 
                    JOIN verses v ON l.verse_id = v.id 
                    WHERE l.user_id = ? 
                    ORDER BY l.timestamp DESC
                """, (user_id,))
            likes = c.fetchall()
        except:
            likes = []
        
        try:
            if db_type == 'postgres':
                c.execute("""
                    SELECT v.reference, v.text, s.timestamp 
                    FROM saves s 
                    JOIN verses v ON s.verse_id = v.id 
                    WHERE s.user_id = %s 
                    ORDER BY s.timestamp DESC
                """, (user_id,))
            else:
                c.execute("""
                    SELECT v.reference, v.text, s.timestamp 
                    FROM saves s 
                    JOIN verses v ON s.verse_id = v.id 
                    WHERE s.user_id = ? 
                    ORDER BY s.timestamp DESC
                """, (user_id,))
            saves = c.fetchall()
        except:
            saves = []
        
        try:
            if db_type == 'postgres':
                c.execute("""
                    SELECT v.reference, c.text, c.timestamp 
                    FROM comments c 
                    JOIN verses v ON c.verse_id = v.id 
                    WHERE c.user_id = %s 
                    ORDER BY c.timestamp DESC
                """, (user_id,))
            else:
                c.execute("""
                    SELECT v.reference, c.text, c.timestamp 
                    FROM comments c 
                    JOIN verses v ON c.verse_id = v.id 
                    WHERE c.user_id = ? 
                    ORDER BY c.timestamp DESC
                """, (user_id,))
            comments = c.fetchall()
        except:
            comments = []
        
        audit_history = []
        
        return render_template('admin_user_details.html', 
                             user=user, 
                             likes=likes, 
                             saves=saves, 
                             comments=comments,
                             audit_history=audit_history)
    except Exception as e:
        logger.error(f"User details error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# ============ BAN/UNBAN API ENDPOINTS (MISSING!) ============

@admin_bp.route('/api/users/<int:user_id>/ban', methods=['POST'])
@admin_required
def ban_user(user_id):
    """Ban a user"""
    data = request.get_json() or {}
    reason = data.get('reason', 'No reason provided')
    duration_hours = data.get('duration_hours')
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        # Check if ban columns exist
        has_banned = check_column_exists(conn, db_type, 'users', 'is_banned')
        has_ban_reason = check_column_exists(conn, db_type, 'users', 'ban_reason')
        has_ban_expires = check_column_exists(conn, db_type, 'users', 'ban_expires_at')
        
        if not has_banned:
            return jsonify({"error": "Ban system not initialized - columns missing"}), 500
        
        # Calculate expiration
        expires_at = None
        if duration_hours:
            expires_at = (datetime.now() + timedelta(hours=int(duration_hours))).isoformat()
        
        # Build update query dynamically based on available columns
        updates = ["is_banned = TRUE" if db_type == 'postgres' else "is_banned = 1"]
        params = []
        
        if has_ban_reason:
            updates.append("ban_reason = %s" if db_type == 'postgres' else "ban_reason = ?")
            params.append(reason)
        
        if has_ban_expires and expires_at:
            updates.append("ban_expires_at = %s" if db_type == 'postgres' else "ban_expires_at = ?")
            params.append(expires_at)
        
        query = f"UPDATE users SET {', '.join(updates)} WHERE id = {'%s' if db_type == 'postgres' else '?'}"
        params.append(user_id)
        
        c.execute(query, params)
        conn.commit()
        
        # Log the action
        try:
            log_action(session.get('user_id'), 'ban_user', user_id, {
                'reason': reason,
                'duration_hours': duration_hours,
                'expires_at': expires_at
            })
        except:
            pass
        
        return jsonify({
            "success": True, 
            "message": "User banned successfully",
            "reason": reason,
            "expires_at": expires_at
        })
        
    except Exception as e:
        logger.error(f"Ban user error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@admin_bp.route('/api/users/<int:user_id>/unban', methods=['POST'])
@admin_required
def unban_user(user_id):
    """Unban a user"""
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        has_banned = check_column_exists(conn, db_type, 'users', 'is_banned')
        if not has_banned:
            return jsonify({"error": "Ban system not initialized"}), 500
        
        # Build update query
        updates = ["is_banned = FALSE" if db_type == 'postgres' else "is_banned = 0"]
        
        if check_column_exists(conn, db_type, 'users', 'ban_reason'):
            updates.append("ban_reason = NULL")
        if check_column_exists(conn, db_type, 'users', 'ban_expires_at'):
            updates.append("ban_expires_at = NULL")
        
        query = f"UPDATE users SET {', '.join(updates)} WHERE id = {'%s' if db_type == 'postgres' else '?'}"
        c.execute(query, (user_id,))
        conn.commit()
        
        # Log the action
        try:
            log_action(session.get('user_id'), 'unban_user', user_id, {})
        except:
            pass
        
        return jsonify({"success": True, "message": "User unbanned successfully"})
        
    except Exception as e:
        logger.error(f"Unban user error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# ============ CONTENT ============

@admin_bp.route('/content')
@admin_required
def admin_content():
    return render_template('admin_content.html')

@admin_bp.route('/api/content/comments')
@admin_required
def api_comments():
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        if db_type == 'postgres':
            c.execute("""
                SELECT c.*, u.name, u.email, v.reference, v.text as verse_text 
                FROM comments c 
                JOIN users u ON c.user_id = u.id 
                JOIN verses v ON c.verse_id = v.id 
                ORDER BY c.timestamp DESC 
                LIMIT 100
            """)
        else:
            c.execute("""
                SELECT c.*, u.name, u.email, v.reference, v.text as verse_text 
                FROM comments c 
                JOIN users u ON c.user_id = u.id 
                JOIN verses v ON c.verse_id = v.id 
                ORDER BY c.timestamp DESC 
                LIMIT 100
            """)
        
        rows = c.fetchall()
        comments = []
        
        for row in rows:
            if isinstance(row, dict):
                comments.append({
                    "id": row.get('id'),
                    "user_id": row.get('user_id'),
                    "user_name": row.get('name', 'Unknown'),
                    "user_email": row.get('email', ''),
                    "verse_id": row.get('verse_id'),
                    "verse_ref": row.get('reference', ''),
                    "verse_text": row.get('verse_text', ''),
                    "text": row.get('text', ''),
                    "timestamp": row.get('timestamp', '')
                })
        
        return jsonify({"comments": comments})
    except Exception as e:
        logger.error(f"Comments API error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@admin_bp.route('/api/content/messages')
@admin_required
def api_messages():
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        if db_type == 'postgres':
            c.execute("""
                SELECT m.*, u.name, u.email 
                FROM community_messages m 
                JOIN users u ON m.user_id = u.id 
                ORDER BY m.timestamp DESC 
                LIMIT 100
            """)
        else:
            c.execute("""
                SELECT m.*, u.name, u.email 
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
                    "id": row.get('id'),
                    "user_id": row.get('user_id'),
                    "user_name": row.get('name', 'Unknown'),
                    "user_email": row.get('email', ''),
                    "text": row.get('text', ''),
                    "timestamp": row.get('timestamp', '')
                })
        
        return jsonify({"messages": messages})
    except Exception as e:
        logger.error(f"Messages API error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@admin_bp.route('/api/content/delete', methods=['POST'])
@admin_required
def delete_content():
    data = request.get_json()
    content_type = data.get('type')
    content_id = data.get('id')
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        if content_type == 'comment':
            if db_type == 'postgres':
                c.execute("DELETE FROM comments WHERE id = %s", (content_id,))
            else:
                c.execute("DELETE FROM comments WHERE id = ?", (content_id,))
        elif content_type == 'message':
            if db_type == 'postgres':
                c.execute("DELETE FROM community_messages WHERE id = %s", (content_id,))
            else:
                c.execute("DELETE FROM community_messages WHERE id = ?", (content_id,))
        
        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Delete content error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# ============ AUDIT ============

@admin_bp.route('/audit')
@admin_required
def admin_audit():
    return render_template('admin_audit.html')

@admin_bp.route('/api/audit')
@admin_required
def api_audit():
    # Return empty for now since audit_logs might not exist
    return jsonify({"logs": []})

@admin_bp.route('/api/check')
def check_admin():
    if 'user_id' not in session:
        return jsonify({"is_admin": False, "logged_in": False})
    
    return jsonify({
        "is_admin": session.get('is_admin', False),
        "logged_in": True,
        "role": session.get('role', 'user')
    })

