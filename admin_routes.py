"""
Admin Extension for Bible AI App
This module adds comprehensive admin functionality to app.py
"""

from flask import Blueprint, render_template, jsonify, request, session, redirect, url_for, flash
from functools import wraps
from datetime import datetime, timedelta
import json
import logging
from app import get_db, get_cursor, check_ban_status, log_action, ADMIN_CODE, MASTER_PASSWORD, IS_POSTGRES

logger = logging.getLogger(__name__)

# Create Blueprint
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# Admin Decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('admin.admin_login'))
        if not session.get('is_admin'):
            return redirect(url_for('admin.admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# ============ ADMIN AUTH ============

@admin_bp.route('/login', methods=['GET', 'POST'])
def admin_login():
    """Dedicated admin login with master password"""
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        password = data.get('password', '')
        user_id = data.get('user_id') or session.get('user_id')
        
        # Check master password
        if password == MASTER_PASSWORD:
            if user_id:
                session['user_id'] = int(user_id)
                session['is_admin'] = True
                session['role'] = 'host'
                log_action(int(user_id), 'admin_login_master', details={'ip': request.remote_addr})
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
    """Main admin dashboard with stats"""
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    stats = {}
    try:
        # User stats
        if db_type == 'postgres':
            c.execute("SELECT COUNT(*) FROM users")
            stats['total_users'] = c.fetchone()['count']
            c.execute("SELECT COUNT(*) FROM users WHERE is_banned = TRUE")
            stats['banned_users'] = c.fetchone()['count']
            c.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1")
            stats['admin_users'] = c.fetchone()['count']
            
            # Content stats
            c.execute("SELECT COUNT(*) FROM verses")
            stats['total_verses'] = c.fetchone()['count']
            c.execute("SELECT COUNT(*) FROM likes")
            stats['total_likes'] = c.fetchone()['count']
            c.execute("SELECT COUNT(*) FROM saves")
            stats['total_saves'] = c.fetchone()['count']
            c.execute("SELECT COUNT(*) FROM comments")
            stats['total_comments'] = c.fetchone()['count']
            
            # Recent activity
            c.execute("""
                SELECT u.name, u.email, u.created_at, u.is_banned 
                FROM users u 
                ORDER BY u.created_at DESC 
                LIMIT 5
            """)
            recent_users = c.fetchall()
            
            # Recent audit logs
            c.execute("""
                SELECT a.*, u.name as admin_name 
                FROM audit_logs a 
                LEFT JOIN users u ON a.admin_id = u.id 
                ORDER BY a.created_at DESC 
                LIMIT 10
            """)
            recent_audit = c.fetchall()
        else:
            c.execute("SELECT COUNT(*) FROM users")
            stats['total_users'] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM users WHERE is_banned = 1")
            stats['banned_users'] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1")
            stats['admin_users'] = c.fetchone()[0]
            
            c.execute("SELECT COUNT(*) FROM verses")
            stats['total_verses'] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM likes")
            stats['total_likes'] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM saves")
            stats['total_saves'] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM comments")
            stats['total_comments'] = c.fetchone()[0]
            
            c.execute("""
                SELECT u.name, u.email, u.created_at, u.is_banned 
                FROM users u 
                ORDER BY u.created_at DESC 
                LIMIT 5
            """)
            recent_users = c.fetchall()
            
            c.execute("""
                SELECT a.*, u.name as admin_name 
                FROM audit_logs a 
                LEFT JOIN users u ON a.admin_id = u.id 
                ORDER BY a.created_at DESC 
                LIMIT 10
            """)
            recent_audit = c.fetchall()
        
        return render_template('admin_dashboard.html', 
                             stats=stats, 
                             recent_users=recent_users, 
                             recent_audit=recent_audit,
                             db_type=db_type)
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# ============ USERS MANAGEMENT ============

@admin_bp.route('/users')
@admin_required
def admin_users():
    """User management page"""
    return render_template('admin_users.html')

@admin_bp.route('/api/users')
@admin_required
def api_users():
    """API endpoint to get all users with filtering"""
    search = request.args.get('search', '')
    status = request.args.get('status', 'all')  # all, banned, admin
    sort = request.args.get('sort', 'newest')
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        query = "SELECT * FROM users WHERE 1=1"
        params = []
        
        if search:
            query += " AND (name ILIKE %s OR email ILIKE %s)" if db_type == 'postgres' else " AND (name LIKE ? OR email LIKE ?)"
            params.extend([f'%{search}%', f'%{search}%'])
        
        if status == 'banned':
            query += " AND is_banned = TRUE" if db_type == 'postgres' else " AND is_banned = 1"
        elif status == 'admin':
            query += " AND is_admin = 1"
        
        if sort == 'newest':
            query += " ORDER BY created_at DESC"
        elif sort == 'oldest':
            query += " ORDER BY created_at ASC"
        elif sort == 'name':
            query += " ORDER BY name ASC"
        
        if db_type == 'postgres':
            c.execute(query, params)
        else:
            c.execute(query, params)
        
        rows = c.fetchall()
        users = []
        
        for row in rows:
            if isinstance(row, dict):
                user = {
                    "id": row['id'],
                    "name": row['name'],
                    "email": row['email'],
                    "picture": row['picture'],
                    "created_at": row['created_at'],
                    "is_admin": bool(row['is_admin']),
                    "is_banned": bool(row['is_banned']),
                    "ban_reason": row['ban_reason'],
                    "ban_expires_at": row['ban_expires_at'],
                    "role": row['role'] or 'user'
                }
            else:
                user = {
                    "id": row[0],
                    "google_id": row[1],
                    "email": row[2],
                    "name": row[3],
                    "picture": row[4],
                    "created_at": row[5],
                    "is_admin": bool(row[6]),
                    "is_banned": bool(row[7]),
                    "ban_expires_at": row[8],
                    "ban_reason": row[9],
                    "role": row[10] if len(row) > 10 else 'user'
                }
            
            # Get additional stats
            if db_type == 'postgres':
                c.execute("SELECT COUNT(*) FROM likes WHERE user_id = %s", (user['id'],))
                user['likes_count'] = c.fetchone()['count']
                c.execute("SELECT COUNT(*) FROM saves WHERE user_id = %s", (user['id'],))
                user['saves_count'] = c.fetchone()['count']
                c.execute("SELECT COUNT(*) FROM comments WHERE user_id = %s", (user['id'],))
                user['comments_count'] = c.fetchone()['count']
            else:
                c.execute("SELECT COUNT(*) FROM likes WHERE user_id = ?", (user['id'],))
                user['likes_count'] = c.fetchone()[0]
                c.execute("SELECT COUNT(*) FROM saves WHERE user_id = ?", (user['id'],))
                user['saves_count'] = c.fetchone()[0]
                c.execute("SELECT COUNT(*) FROM comments WHERE user_id = ?", (user['id'],))
                user['comments_count'] = c.fetchone()[0]
            
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
    """Detailed user view"""
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
        
        if isinstance(row, dict):
            user = {
                "id": row['id'],
                "google_id": row['google_id'],
                "name": row['name'],
                "email": row['email'],
                "picture": row['picture'],
                "created_at": row['created_at'],
                "is_admin": bool(row['is_admin']),
                "is_banned": bool(row['is_banned']),
                "ban_reason": row['ban_reason'],
                "ban_expires_at": row['ban_expires_at'],
                "role": row['role'] or 'user'
            }
        else:
            user = {
                "id": row[0],
                "google_id": row[1],
                "name": row[3],
                "email": row[2],
                "picture": row[4],
                "created_at": row[5],
                "is_admin": bool(row[6]),
                "is_banned": bool(row[7]),
                "ban_expires_at": row[8],
                "ban_reason": row[9],
                "role": row[10] if len(row) > 10 else 'user'
            }
        
        # Get user activity
        if db_type == 'postgres':
            c.execute("""
                SELECT v.reference, v.text, l.timestamp 
                FROM likes l 
                JOIN verses v ON l.verse_id = v.id 
                WHERE l.user_id = %s 
                ORDER BY l.timestamp DESC
            """, (user_id,))
            likes = c.fetchall()
            
            c.execute("""
                SELECT v.reference, v.text, s.timestamp 
                FROM saves s 
                JOIN verses v ON s.verse_id = v.id 
                WHERE s.user_id = %s 
                ORDER BY s.timestamp DESC
            """, (user_id,))
            saves = c.fetchall()
            
            c.execute("""
                SELECT v.reference, c.text, c.timestamp 
                FROM comments c 
                JOIN verses v ON c.verse_id = v.id 
                WHERE c.user_id = %s 
                ORDER BY c.timestamp DESC
            """, (user_id,))
            comments = c.fetchall()
            
            c.execute("""
                SELECT * FROM audit_logs 
                WHERE target_user_id = %s 
                ORDER BY created_at DESC
            """, (user_id,))
            audit_history = c.fetchall()
        else:
            c.execute("""
                SELECT v.reference, v.text, l.timestamp 
                FROM likes l 
                JOIN verses v ON l.verse_id = v.id 
                WHERE l.user_id = ? 
                ORDER BY l.timestamp DESC
            """, (user_id,))
            likes = c.fetchall()
            
            c.execute("""
                SELECT v.reference, v.text, s.timestamp 
                FROM saves s 
                JOIN verses v ON s.verse_id = v.id 
                WHERE s.user_id = ? 
                ORDER BY s.timestamp DESC
            """, (user_id,))
            saves = c.fetchall()
            
            c.execute("""
                SELECT v.reference, c.text, c.timestamp 
                FROM comments c 
                JOIN verses v ON c.verse_id = v.id 
                WHERE c.user_id = ? 
                ORDER BY c.timestamp DESC
            """, (user_id,))
            comments = c.fetchall()
            
            c.execute("""
                SELECT * FROM audit_logs 
                WHERE target_user_id = ? 
                ORDER BY created_at DESC
            """, (user_id,))
            audit_history = c.fetchall()
        
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

# ============ USER ACTIONS ============

@admin_bp.route('/api/user/<int:user_id>/ban', methods=['POST'])
@admin_required
def ban_user(user_id):
    """Ban or unban user"""
    data = request.get_json()
    action = data.get('action', 'ban')  # ban or unban
    reason = data.get('reason', '')
    duration = data.get('duration')  # hours, or null for permanent
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        if action == 'ban':
            expires_at = None
            if duration:
                expires_at = (datetime.now() + timedelta(hours=int(duration))).isoformat()
            
            if db_type == 'postgres':
                c.execute("""
                    UPDATE users 
                    SET is_banned = TRUE, ban_reason = %s, ban_expires_at = %s 
                    WHERE id = %s
                """, (reason, expires_at, user_id))
            else:
                c.execute("""
                    UPDATE users 
                    SET is_banned = 1, ban_reason = ?, ban_expires_at = ? 
                    WHERE id = ?
                """, (reason, expires_at, user_id))
            
            log_action(session['user_id'], 'user_banned', target_user_id=user_id, 
                      details={'reason': reason, 'expires': expires_at})
        else:
            if db_type == 'postgres':
                c.execute("""
                    UPDATE users 
                    SET is_banned = FALSE, ban_reason = NULL, ban_expires_at = NULL 
                    WHERE id = %s
                """, (user_id,))
            else:
                c.execute("""
                    UPDATE users 
                    SET is_banned = 0, ban_reason = NULL, ban_expires_at = NULL 
                    WHERE id = ?
                """, (user_id,))
            
            log_action(session['user_id'], 'user_unbanned', target_user_id=user_id)
        
        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Ban error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@admin_bp.route('/api/user/<int:user_id>/role', methods=['POST'])
@admin_required
def update_user_role(user_id):
    """Update user role"""
    data = request.get_json()
    role = data.get('role', 'user')  # user, moderator, admin
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        is_admin = 1 if role in ['admin', 'host'] else 0
        
        if db_type == 'postgres':
            c.execute("""
                UPDATE users 
                SET role = %s, is_admin = %s 
                WHERE id = %s
            """, (role, is_admin, user_id))
        else:
            c.execute("""
                UPDATE users 
                SET role = ?, is_admin = ? 
                WHERE id = ?
            """, (role, is_admin, user_id))
        
        conn.commit()
        log_action(session['user_id'], 'role_updated', target_user_id=user_id, 
                  details={'new_role': role})
        return jsonify({"success": True, "role": role})
    except Exception as e:
        logger.error(f"Role update error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# ============ AUDIT LOGS ============

@admin_bp.route('/audit')
@admin_required
def admin_audit():
    """Audit logs page"""
    return render_template('admin_audit.html')

@admin_bp.route('/api/audit')
@admin_required
def api_audit():
    """Get audit logs with filtering"""
    action_type = request.args.get('action', 'all')
    admin_id = request.args.get('admin_id')
    date_from = request.args.get('from')
    date_to = request.args.get('to')
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        query = """
            SELECT a.*, u.name as admin_name, t.name as target_name 
            FROM audit_logs a 
            LEFT JOIN users u ON a.admin_id = u.id 
            LEFT JOIN users t ON a.target_user_id = t.id 
            WHERE 1=1
        """
        params = []
        
        if action_type != 'all':
            query += " AND a.action = %s" if db_type == 'postgres' else " AND a.action = ?"
            params.append(action_type)
        
        if admin_id:
            query += " AND a.admin_id = %s" if db_type == 'postgres' else " AND a.admin_id = ?"
            params.append(int(admin_id))
        
        if date_from:
            query += " AND a.created_at >= %s" if db_type == 'postgres' else " AND a.created_at >= ?"
            params.append(date_from)
        
        if date_to:
            query += " AND a.created_at <= %s" if db_type == 'postgres' else " AND a.created_at <= ?"
            params.append(date_to)
        
        query += " ORDER BY a.created_at DESC LIMIT 100"
        
        if db_type == 'postgres':
            c.execute(query, params)
        else:
            c.execute(query, params)
        
        rows = c.fetchall()
        logs = []
        
        for row in rows:
            if isinstance(row, dict):
                logs.append({
                    "id": row['id'],
                    "admin_id": row['admin_id'],
                    "admin_name": row['admin_name'],
                    "action": row['action'],
                    "target_user_id": row['target_user_id'],
                    "target_name": row['target_name'],
                    "details": row['details'],
                    "created_at": row['created_at']
                })
            else:
                logs.append({
                    "id": row[0],
                    "admin_id": row[1],
                    "admin_name": row[6],
                    "action": row[2],
                    "target_user_id": row[3],
                    "target_name": row[7],
                    "details": row[4],
                    "created_at": row[5]
                })
        
        return jsonify({"logs": logs})
    except Exception as e:
        logger.error(f"Audit API error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# ============ CONTENT MODERATION ============

@admin_bp.route('/content')
@admin_required
def admin_content():
    """Content moderation page"""
    return render_template('admin_content.html')

@admin_bp.route('/api/content/comments')
@admin_required
def api_comments():
    """Get all comments for moderation"""
    status = request.args.get('status', 'all')  # all, reported, recent
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        query = """
            SELECT c.*, u.name, u.email, v.reference, v.text as verse_text 
            FROM comments c 
            JOIN users u ON c.user_id = u.id 
            JOIN verses v ON c.verse_id = v.id 
            ORDER BY c.timestamp DESC 
            LIMIT 100
        """
        
        if db_type == 'postgres':
            c.execute(query)
        else:
            c.execute(query)
        
        rows = c.fetchall()
        comments = []
        
        for row in rows:
            if isinstance(row, dict):
                comments.append({
                    "id": row['id'],
                    "user_id": row['user_id'],
                    "user_name": row['name'],
                    "user_email": row['email'],
                    "verse_id": row['verse_id'],
                    "verse_ref": row['reference'],
                    "verse_text": row['verse_text'],
                    "text": row['text'],
                    "timestamp": row['timestamp']
                })
            else:
                comments.append({
                    "id": row[0],
                    "user_id": row[1],
                    "verse_id": row[2],
                    "text": row[3],
                    "timestamp": row[4],
                    "user_name": row[7],
                    "user_email": row[8],
                    "verse_ref": row[9],
                    "verse_text": row[10]
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
    """Get all community messages for moderation"""
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
                    "id": row['id'],
                    "user_id": row['user_id'],
                    "user_name": row['name'],
                    "user_email": row['email'],
                    "text": row['text'],
                    "timestamp": row['timestamp']
                })
            else:
                messages.append({
                    "id": row[0],
                    "user_id": row[1],
                    "text": row[2],
                    "timestamp": row[3],
                    "user_name": row[5],
                    "user_email": row[6]
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
    """Delete comment or message"""
    data = request.get_json()
    content_type = data.get('type')  # comment or message
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
        log_action(session['user_id'], f'{content_type}_deleted', details={'content_id': content_id})
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Delete content error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# ============ SYSTEM SETTINGS ============

@admin_bp.route('/api/stats/detailed')
@admin_required
def api_detailed_stats():
    """Get detailed system statistics"""
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        stats = {}
        
        # Daily active users (last 7 days)
        if db_type == 'postgres':
            c.execute("""
                SELECT DATE(created_at) as date, COUNT(*) as count 
                FROM users 
                WHERE created_at >= NOW() - INTERVAL '7 days'
                GROUP BY DATE(created_at) 
                ORDER BY date
            """)
            stats['daily_users'] = c.fetchall()
            
            # Most liked verses
            c.execute("""
                SELECT v.reference, v.text, COUNT(l.id) as like_count 
                FROM verses v 
                JOIN likes l ON v.id = l.verse_id 
                GROUP BY v.id 
                ORDER BY like_count DESC 
                LIMIT 10
            """)
            stats['top_verses'] = c.fetchall()
            
            # Most active users
            c.execute("""
                SELECT u.name, u.email, 
                       COUNT(DISTINCT l.id) as likes,
                       COUNT(DISTINCT s.id) as saves,
                       COUNT(DISTINCT c.id) as comments
                FROM users u
                LEFT JOIN likes l ON u.id = l.user_id
                LEFT JOIN saves s ON u.id = s.user_id
                LEFT JOIN comments c ON u.id = c.user_id
                GROUP BY u.id
                ORDER BY (COUNT(DISTINCT l.id) + COUNT(DISTINCT s.id) + COUNT(DISTINCT c.id)) DESC
                LIMIT 10
            """)
            stats['active_users'] = c.fetchall()
        else:
            c.execute("""
                SELECT DATE(created_at) as date, COUNT(*) as count 
                FROM users 
                WHERE created_at >= datetime('now', '-7 days')
                GROUP BY DATE(created_at) 
                ORDER BY date
            """)
            stats['daily_users'] = c.fetchall()
            
            c.execute("""
                SELECT v.reference, v.text, COUNT(l.id) as like_count 
                FROM verses v 
                JOIN likes l ON v.id = l.verse_id 
                GROUP BY v.id 
                ORDER BY like_count DESC 
                LIMIT 10
            """)
            stats['top_verses'] = c.fetchall()
            
            c.execute("""
                SELECT u.name, u.email, 
                       COUNT(DISTINCT l.id) as likes,
                       COUNT(DISTINCT s.id) as saves,
                       COUNT(DISTINCT c.id) as comments
                FROM users u
                LEFT JOIN likes l ON u.id = l.user_id
                LEFT JOIN saves s ON u.id = s.user_id
                LEFT JOIN comments c ON u.id = c.user_id
                GROUP BY u.id
                ORDER BY (COUNT(DISTINCT l.id) + COUNT(DISTINCT s.id) + COUNT(DISTINCT c.id)) DESC
                LIMIT 10
            """)
            stats['active_users'] = c.fetchall()
        
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Detailed stats error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# ============ API ENDPOINTS FOR MAIN APP ============

@admin_bp.route('/api/check')
def check_admin():
    """Check if current user is admin"""
    if 'user_id' not in session:
        return jsonify({"is_admin": False, "logged_in": False})
    
    return jsonify({
        "is_admin": session.get('is_admin', False),
        "logged_in": True,
        "role": session.get('role', 'user')
    })