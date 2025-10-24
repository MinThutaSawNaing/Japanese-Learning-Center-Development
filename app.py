import sqlite3
import os
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import base64
from io import BytesIO
import random
import string
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
import logging

app = Flask(__name__)
app.secret_key = 'japanese_learning_secret_key_change_in_production'  # Change this in production

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True)

# Create static folders if they don't exist
os.makedirs('static/images', exist_ok=True)
os.makedirs('uploads', exist_ok=True)
os.makedirs('uploads/support', exist_ok=True)
os.makedirs('uploads/teacher', exist_ok=True)

# Database initialization
def init_db():
    conn = sqlite3.connect('japanese_learning.db')
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0
    )
    ''')
    
    # Create courses table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS courses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        level TEXT UNIQUE NOT NULL,
        description TEXT NOT NULL,
        content TEXT NOT NULL
    )
    ''')
    
    # Create purchases table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS purchases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        course_id INTEGER NOT NULL,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (course_id) REFERENCES courses (id)
    )
    ''')
    
    # Create support_messages table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS support_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        message_type TEXT NOT NULL,
        subject TEXT NOT NULL,
        message TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Create teacher_messages table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS teacher_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        subject TEXT NOT NULL,
        message TEXT NOT NULL,
        file_path TEXT,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Create support_replies table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS support_replies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id INTEGER NOT NULL,
        reply TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (message_id) REFERENCES support_messages (id)
    )
    ''')
    
    # Create teacher_replies table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS teacher_replies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id INTEGER NOT NULL,
        reply TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (message_id) REFERENCES teacher_messages (id)
    )
    ''')
    
    # Check if admin user exists, if not create one
    cursor.execute('SELECT * FROM users WHERE email = "admin@example.com"')
    if not cursor.fetchone():
        cursor.execute('''
        INSERT INTO users (email, password_hash, is_admin)
        VALUES (?, ?, ?)
        ''', ('admin@example.com', generate_password_hash('admin123'), 1))
    
    # Check if courses exist, if not create them
    cursor.execute('SELECT * FROM courses')
    if not cursor.fetchone():
        courses_data = [
            ('N5', 'Beginner Level - Basic Japanese', 
            'N5 Course Content: Hiragana, Katakana, basic grammar, simple conversations. This level focuses on understanding basic Japanese phrases and expressions used in daily life.\n\nသင်ခန်းစာများ အားဝယ်ယူရာတွင်လွယ်ကူစေရန် KBZ payဖြင့်ငွေချေနိုင်ပါတယ် ငွေချေရန် scan ဖတ်ပါ note တွင်ဝယ်ယူသည့် သင်ခန်းစာနံပါတ်ကိုထည့်သွင်းရေးသားပေးပါ။ ဥပမာ: N5, N3။ ငွေလွှဲပြီးတစ်နာရီအတွင်း approve လုပ်ပေးပါမယ်။ ကျေးဇူးတင်ပါတယ်။'),
            ('N4', 'Elementary Level - Basic Japanese', 
            'N4 Course Content: More grammar structures, vocabulary building, reading comprehension. Students learn to understand basic Japanese and read simple sentences.\n\nသင်ခန်းစာများ အားဝယ်ယူရာတွင်လွယ်ကူစေရန် KBZ payဖြင့်ငွေချေနိုင်ပါတယ် ငွေချေရန် scan ဖတ်ပါ note တွင်ဝယ်ယူသည့် သင်ခန်းစာနံပါတ်ကိုထည့်သွင်းရေးသားပေးပါ။ ဥပမာ: N5, N3။ ငွေလွှဲပြီးတစ်နာရီအတွင်း approve လုပ်ပေးပါမယ်။ ကျေးဇူးတင်ပါတယ်။'),
            ('N3', 'Intermediate Level - Japanese', 
            'N3 Course Content: Complex grammar, kanji, reading passages, listening exercises. This level bridges the gap between basic and advanced Japanese.\n\nသင်ခန်းစာများ အားဝယ်ယူရာတွင်လွယ်ကူစေရန် KBZ payဖြင့်ငွေချေနိုင်ပါတယ် ငွေချေရန် scan ဖတ်ပါ note တွင်ဝယ်ယူသည့် သင်ခန်းစာနံပါတ်ကိုထည့်သွင်းရေးသားပေးပါ။ ဥပမာ: N5, N3။ ငွေလွှဲပြီးတစ်နာရီအတွင်း approve လုပ်ပေးပါမယ်။ ကျေးဇူးတင်ပါတယ်။'),
            ('N2', 'Upper Intermediate Level - Japanese', 
            'N2 Course Content: Advanced grammar, extensive vocabulary, complex reading materials. Students can understand Japanese used in everyday situations and in a variety of circumstances.\n\nသင်ခန်းစာများ အားဝယ်ယူရာတွင်လွယ်ကူစေရန် KBZ payဖြင့်ငွေချေနိုင်ပါတယ် ငွေချေရန် scan ဖတ်ပါ note တွင်ဝယ်ယူသည့် သင်ခန်းစာနံပါတ်ကိုထည့်သွင်းရေးသားပေးပါ။ ဥပမာ: N5, N3။ ငွေလွှဲပြီးတစ်နာရီအတွင်း approve လုပ်ပေးပါမယ်။ ကျေးဇူးတင်ပါတယ်။'),
            ('N1', 'Advanced Level - Japanese', 
            'N1 Course Content: Native-level fluency, specialized vocabulary, nuanced expressions. This is the highest level of Japanese language proficiency.\n\nသင်ခန်းစာများ အားဝယ်ယူရာတွင်လွယ်ကူစေရန် KBZ payဖြင့်ငွေချေနိုင်ပါတယ် ငွေချေရန် scan ဖတ်ပါ note တွင်ဝယ်ယူသည့် သင်ခန်းစာနံပါတ်ကိုထည့်သွင်းရေးသားပေးပါ။ ဥပမာ: N5, N3။ ငွေလွှဲပြီးတစ်နာရီအတွင်း approve လုပ်ပေးပါမယ်။ ကျေးဇူးတင်ပါတယ်။')
        ]
        cursor.executemany('INSERT INTO courses (level, description, content) VALUES (?, ?, ?)', courses_data)
            
    conn.commit()
    conn.close()

# Initialize database on app start
init_db()

# Helper function to get database connection
def get_db():
    conn = sqlite3.connect('japanese_learning.db')
    conn.row_factory = sqlite3.Row
    return conn

# Generate random 4-digit CAPTCHA
def generate_captcha():
    captcha = ''.join(random.choices(string.digits, k=4))
    session['captcha'] = captcha
    return captcha

# Decorator to require login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Login required', 'redirect': '/#auth'})
        return f(*args, **kwargs)
    return decorated_function

# Decorator to require admin login
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('is_admin') != 1:
            return jsonify({'success': False, 'message': 'Admin access required'})
        return f(*args, **kwargs)
    return decorated_function

# Socket.IO event handlers
@socketio.on('connect')
def handle_connect():
    logger.info(f"Client connected: {request.sid}")
    
    # Check if user is logged in
    if 'user_id' in session:
        user_id = session['user_id']
        is_admin = session.get('is_admin', 0)
        
        # Join user-specific room
        join_room(f"user_{user_id}")
        logger.info(f"User {user_id} joined room user_{user_id}")
        
        # Join admin room if user is admin
        if is_admin == 1:
            join_room('admin')
            logger.info(f"Admin {user_id} joined admin room")
            
            # Send current purchases to newly connected admin
            try:
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute('''
                SELECT p.id, u.email, c.level, p.status
                FROM purchases p
                JOIN users u ON p.user_id = u.id
                JOIN courses c ON p.course_id = c.id
                ORDER BY p.id DESC
                ''')
                purchases = [dict(row) for row in cursor.fetchall()]
                
                # Send support messages to admin
                cursor.execute('''
                SELECT sm.id, u.email, sm.message_type, sm.subject, sm.message, sm.status
                FROM support_messages sm
                JOIN users u ON sm.user_id = u.id
                ORDER BY sm.id DESC
                ''')
                support_messages = [dict(row) for row in cursor.fetchall()]
                
                # Send teacher messages to admin
                cursor.execute('''
                SELECT tm.id, u.email, tm.subject, tm.message, tm.file_path, tm.status
                FROM teacher_messages tm
                JOIN users u ON tm.user_id = u.id
                ORDER BY tm.id DESC
                ''')
                teacher_messages = [dict(row) for row in cursor.fetchall()]
                
                conn.close()
                
                emit('initial_purchases', {'purchases': purchases})
                emit('initial_support_messages', {'messages': support_messages})
                emit('initial_teacher_messages', {'messages': teacher_messages})
            except Exception as e:
                logger.error(f"Error sending initial data: {e}")

@socketio.on('disconnect')
def handle_disconnect():
    logger.info(f"Client disconnected: {request.sid}")

@socketio.on('join_user_room')
def handle_join_user_room(data):
    if 'user_id' in session:
        user_id = session['user_id']
        join_room(f"user_{user_id}")
        emit('room_joined', {'room': f"user_{user_id}"})
        logger.info(f"User {user_id} explicitly joined room user_{user_id}")

@socketio.on('join_admin_room')
def handle_join_admin_room():
    if 'user_id' in session and session.get('is_admin') == 1:
        join_room('admin')
        emit('room_joined', {'room': 'admin'})
        logger.info(f"Admin {session['user_id']} explicitly joined admin room")

# Routes
@app.route('/')
def index():
    # Generate a new CAPTCHA for the session
    generate_captcha()
    return render_template('main.html')

@app.route('/static/images/<filename>')
def serve_image(filename):
    return send_from_directory('static/images', filename)

@app.route('/get-captcha')
def get_captcha():
    captcha = generate_captcha()
    return jsonify({'captcha': captcha})

@app.route('/register', methods=['POST'])
def register():
    email = request.form.get('email')
    password = request.form.get('password')
    captcha = request.form.get('captcha')
    
    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password are required'})
    
    # Verify CAPTCHA
    if not captcha or captcha != session.get('captcha'):
        return jsonify({'success': False, 'message': 'Invalid CAPTCHA'})
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Check if user already exists
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        if cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'message': 'Email already exists'})
        
        # Create new user
        password_hash = generate_password_hash(password)
        cursor.execute('INSERT INTO users (email, password_hash) VALUES (?, ?)', (email, password_hash))
        conn.commit()
        
        # Get the new user's ID
        user_id = cursor.lastrowid
        conn.close()
        
        # Log in the new user
        session['user_id'] = user_id
        session['is_admin'] = 0
        
        # Generate a new CAPTCHA after successful registration
        generate_captcha()
        
        return jsonify({'success': True, 'message': 'Registration successful', 'user_id': user_id})
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        conn.close()
        return jsonify({'success': False, 'message': 'Registration failed'})

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')
    captcha = request.form.get('captcha')
    
    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password are required'})
    
    # Verify CAPTCHA
    if not captcha or captcha != session.get('captcha'):
        return jsonify({'success': False, 'message': 'Invalid CAPTCHA'})
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        conn.close()
        
        if not user or not check_password_hash(user['password_hash'], password):
            return jsonify({'success': False, 'message': 'Invalid email or password'})
        
        session['user_id'] = user['id']
        session['is_admin'] = user['is_admin']
        
        # Generate a new CAPTCHA after successful login
        generate_captcha()
        
        return jsonify({
            'success': True, 
            'message': 'Login successful', 
            'is_admin': user['is_admin'],
            'user_id': user['id']
        })
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        conn.close()
        return jsonify({'success': False, 'message': 'Login failed'})

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    is_admin = session.get('is_admin', 0)
    
    session.clear()
    
    # Generate a new CAPTCHA after logout
    generate_captcha()
    
    # Notify Socket.IO about logout
    if user_id:
        socketio.emit('user_logout', {'user_id': user_id}, room='admin')
        logger.info(f"User {user_id} logged out")
    
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/courses')
@login_required
def courses():
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Get all courses
        cursor.execute('SELECT * FROM courses')
        courses = cursor.fetchall()
        
        # Get user's purchases
        cursor.execute('SELECT course_id, status FROM purchases WHERE user_id = ?', (session['user_id'],))
        purchases = {row['course_id']: row['status'] for row in cursor.fetchall()}
        
        conn.close()
        
        courses_data = []
        for course in courses:
            course_dict = dict(course)
            course_dict['purchased'] = course['id'] in purchases
            course_dict['status'] = purchases.get(course['id'], None)
            courses_data.append(course_dict)
        
        return jsonify({'courses': courses_data})
        
    except Exception as e:
        logger.error(f"Load courses error: {e}")
        conn.close()
        return jsonify({'success': False, 'message': 'Failed to load courses'})

@app.route('/purchase/<level>')
@login_required
def purchase(level):
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Get course ID
        cursor.execute('SELECT id FROM courses WHERE level = ?', (level,))
        course = cursor.fetchone()
        
        if not course:
            conn.close()
            return jsonify({'success': False, 'message': 'Course not found'})
        
        # Check if already purchased
        cursor.execute('SELECT id, status FROM purchases WHERE user_id = ? AND course_id = ?', 
                      (session['user_id'], course['id']))
        purchase = cursor.fetchone()
        
        if purchase:
            conn.close()
            return jsonify({
                'success': False, 
                'message': 'Already purchased', 
                'status': purchase['status']
            })
        
        # Create a new purchase record with pending status
        cursor.execute('INSERT INTO purchases (user_id, course_id, status) VALUES (?, ?, ?)',
                      (session['user_id'], course['id'], 'pending'))
        conn.commit()
        
        # Get purchase ID
        purchase_id = cursor.lastrowid
        
        # Get user email for notification
        cursor.execute('SELECT email FROM users WHERE id = ?', (session['user_id'],))
        user_email = cursor.fetchone()[0]
        
        conn.close()
        
        # Use the proper URL for the QR code
        qr_code_url = url_for('serve_image', filename='kpay.jpg', _external=True)
        
        # Prepare purchase data for notification
        purchase_data = {
            'id': purchase_id,
            'user_email': user_email,
            'course_level': level,
            'course_id': course['id'],
            'status': 'pending',
            'user_id': session['user_id']
        }
        
        # Emit real-time notification to admin room
        socketio.emit('new_purchase', purchase_data, room='admin')
        logger.info(f"New purchase emitted: {purchase_data}")
        
        return jsonify({
            'success': True, 
            'message': 'Purchase initiated. Please complete payment.',
            'qr_code_url': qr_code_url,
            'purchase_id': purchase_id
        })
        
    except Exception as e:
        logger.error(f"Purchase error: {e}")
        conn.close()
        return jsonify({'success': False, 'message': 'Purchase failed'})

@app.route('/admin')
def admin_login_page():
    # Generate a new CAPTCHA for the session
    generate_captcha()
    return render_template('main.html', admin_login=True)

@app.route('/admin/login', methods=['POST'])
def admin_login():
    email = request.form.get('email')
    password = request.form.get('password')
    captcha = request.form.get('captcha')
    
    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password are required'})
    
    # Verify CAPTCHA
    if not captcha or captcha != session.get('captcha'):
        return jsonify({'success': False, 'message': 'Invalid CAPTCHA'})
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT * FROM users WHERE email = ? AND is_admin = 1', (email,))
        admin = cursor.fetchone()
        conn.close()
        
        if not admin or not check_password_hash(admin['password_hash'], password):
            return jsonify({'success': False, 'message': 'Invalid admin credentials'})
        
        session['user_id'] = admin['id']
        session['is_admin'] = 1
        
        # Generate a new CAPTCHA after successful admin login
        generate_captcha()
        
        return jsonify({
            'success': True, 
            'message': 'Admin login successful',
            'user_id': admin['id']
        })
        
    except Exception as e:
        logger.error(f"Admin login error: {e}")
        conn.close()
        return jsonify({'success': False, 'message': 'Admin login failed'})

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Get all purchases with user and course info
        cursor.execute('''
        SELECT p.id, u.email, c.level, p.status
        FROM purchases p
        JOIN users u ON p.user_id = u.id
        JOIN courses c ON p.course_id = c.id
        ORDER BY p.id DESC
        ''')
        purchases = cursor.fetchall()
        
        # Get all support messages with user info
        cursor.execute('''
        SELECT sm.id, u.email, sm.message_type, sm.subject, sm.message, sm.status
        FROM support_messages sm
        JOIN users u ON sm.user_id = u.id
        ORDER BY sm.id DESC
        ''')
        support_messages = cursor.fetchall()
        
        # Get all teacher messages with user info
        cursor.execute('''
        SELECT tm.id, u.email, tm.subject, tm.message, tm.file_path, tm.status
        FROM teacher_messages tm
        JOIN users u ON tm.user_id = u.id
        ORDER BY tm.id DESC
        ''')
        teacher_messages = cursor.fetchall()
        
        conn.close()
        
        return render_template('main.html', admin_dashboard=True, 
                             purchases=purchases, 
                             support_messages=support_messages,
                             teacher_messages=teacher_messages)
        
    except Exception as e:
        logger.error(f"Admin dashboard error: {e}")
        conn.close()
        return render_template('main.html', admin_dashboard=True, 
                             purchases=[], 
                             support_messages=[],
                             teacher_messages=[])

@app.route('/admin/dashboard/data')
@admin_required
def admin_dashboard_data():
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Get all purchases with user and course info
        cursor.execute('''
        SELECT p.id, u.email, c.level, p.status, p.user_id
        FROM purchases p
        JOIN users u ON p.user_id = u.id
        JOIN courses c ON p.course_id = c.id
        ORDER BY p.id DESC
        ''')
        purchases = [dict(row) for row in cursor.fetchall()]
        
        # Get all support messages with user info
        cursor.execute('''
        SELECT sm.id, u.email, sm.message_type, sm.subject, sm.message, sm.status, sm.user_id
        FROM support_messages sm
        JOIN users u ON sm.user_id = u.id
        ORDER BY sm.id DESC
        ''')
        support_messages = [dict(row) for row in cursor.fetchall()]
        
        # Get all teacher messages with user info
        cursor.execute('''
        SELECT tm.id, u.email, tm.subject, tm.message, tm.file_path, tm.status, tm.user_id
        FROM teacher_messages tm
        JOIN users u ON tm.user_id = u.id
        ORDER BY tm.id DESC
        ''')
        teacher_messages = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return jsonify({
            'purchases': purchases, 
            'support_messages': support_messages,
            'teacher_messages': teacher_messages
        })
        
    except Exception as e:
        logger.error(f"Admin dashboard data error: {e}")
        conn.close()
        return jsonify({
            'purchases': [], 
            'support_messages': [],
            'teacher_messages': []
        })

@app.route('/admin/approve/<int:purchase_id>', methods=['POST'])
@admin_required
def approve_purchase(purchase_id):
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Get purchase details before updating
        cursor.execute('''
        SELECT p.user_id, c.level, u.email
        FROM purchases p
        JOIN courses c ON p.course_id = c.id
        JOIN users u ON p.user_id = u.id
        WHERE p.id = ?
        ''', (purchase_id,))
        purchase_data = cursor.fetchone()
        
        if not purchase_data:
            conn.close()
            return jsonify({'success': False, 'message': 'Purchase not found'})
        
        # Update purchase status
        cursor.execute('UPDATE purchases SET status = "approved" WHERE id = ?', (purchase_id,))
        conn.commit()
        
        # Get updated purchase data
        cursor.execute('''
        SELECT p.id, u.email, c.level, p.status, p.user_id
        FROM purchases p
        JOIN users u ON p.user_id = u.id
        JOIN courses c ON p.course_id = c.id
        WHERE p.id = ?
        ''', (purchase_id,))
        updated_purchase = dict(cursor.fetchone())
        
        conn.close()
        
        # Emit real-time notification to admin room
        socketio.emit('purchase_updated', {
            'purchase': updated_purchase,
            'action': 'approved'
        }, room='admin')
        
        # Emit real-time notification to specific user
        socketio.emit('purchase_status_changed', {
            'course_level': purchase_data['level'],
            'status': 'approved',
            'message': f'Your purchase for {purchase_data["level"]} has been approved!'
        }, room=f"user_{purchase_data['user_id']}")
        
        logger.info(f"Purchase {purchase_id} approved for user {purchase_data['user_id']}")
        
        return jsonify({'success': True, 'message': 'Purchase approved'})
        
    except Exception as e:
        logger.error(f"Approve purchase error: {e}")
        conn.close()
        return jsonify({'success': False, 'message': 'Failed to approve purchase'})

@app.route('/admin/reject/<int:purchase_id>', methods=['POST'])
@admin_required
def reject_purchase(purchase_id):
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Get purchase details before updating
        cursor.execute('''
        SELECT p.user_id, c.level, u.email
        FROM purchases p
        JOIN courses c ON p.course_id = c.id
        JOIN users u ON p.user_id = u.id
        WHERE p.id = ?
        ''', (purchase_id,))
        purchase_data = cursor.fetchone()
        
        if not purchase_data:
            conn.close()
            return jsonify({'success': False, 'message': 'Purchase not found'})
        
        # Update purchase status
        cursor.execute('UPDATE purchases SET status = "rejected" WHERE id = ?', (purchase_id,))
        conn.commit()
        
        # Get updated purchase data
        cursor.execute('''
        SELECT p.id, u.email, c.level, p.status, p.user_id
        FROM purchases p
        JOIN users u ON p.user_id = u.id
        JOIN courses c ON p.course_id = c.id
        WHERE p.id = ?
        ''', (purchase_id,))
        updated_purchase = dict(cursor.fetchone())
        
        conn.close()
        
        # Emit real-time notification to admin room
        socketio.emit('purchase_updated', {
            'purchase': updated_purchase,
            'action': 'rejected'
        }, room='admin')
        
        # Emit real-time notification to specific user
        socketio.emit('purchase_status_changed', {
            'course_level': purchase_data['level'],
            'status': 'rejected',
            'message': f'Your purchase for {purchase_data["level"]} has been rejected'
        }, room=f"user_{purchase_data['user_id']}")
        
        logger.info(f"Purchase {purchase_id} rejected for user {purchase_data['user_id']}")
        
        return jsonify({'success': True, 'message': 'Purchase rejected'})
        
    except Exception as e:
        logger.error(f"Reject purchase error: {e}")
        conn.close()
        return jsonify({'success': False, 'message': 'Failed to reject purchase'})

@app.route('/support')
@login_required
def support():
    return render_template('main.html', support=True)

@app.route('/support/submit', methods=['POST'])
@login_required
def submit_support():
    message_type = request.form.get('message_type')
    subject = request.form.get('subject')
    message = request.form.get('message')
    
    if not message_type or not subject or not message:
        return jsonify({'success': False, 'message': 'All fields are required'})
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Insert the support message
        cursor.execute('''
        INSERT INTO support_messages (user_id, message_type, subject, message)
        VALUES (?, ?, ?, ?)
        ''', (session['user_id'], message_type, subject, message))
        conn.commit()
        
        # Get the message ID
        message_id = cursor.lastrowid
        
        # Get user email for notification
        cursor.execute('SELECT email FROM users WHERE id = ?', (session['user_id'],))
        user_email = cursor.fetchone()[0]
        
        conn.close()
        
        # Prepare message data for notification
        message_data = {
            'id': message_id,
            'user_email': user_email,
            'message_type': message_type,
            'subject': subject,
            'message': message,
            'status': 'pending',
            'user_id': session['user_id']
        }
        
        # Emit real-time notification to admin room
        socketio.emit('new_support_message', message_data, room='admin')
        logger.info(f"New support message emitted: {message_data}")
        
        return jsonify({
            'success': True, 
            'message': 'Your message has been sent. We will get back to you soon.',
            'message_id': message_id
        })
        
    except Exception as e:
        logger.error(f"Submit support message error: {e}")
        conn.close()
        return jsonify({'success': False, 'message': 'Failed to send message'})

@app.route('/teacher/submit', methods=['POST'])
@login_required
def submit_teacher_message():
    subject = request.form.get('subject')
    message = request.form.get('message')
    
    if not subject or not message:
        return jsonify({'success': False, 'message': 'Subject and message are required'})
    
    file_path = None
    if 'file' in request.files:
        file = request.files['file']
        if file and file.filename:
            # Check file extension
            allowed_extensions = {'docx', 'pdf', 'txt', 'jpeg', 'jpg', 'png'}
            if '.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in allowed_extensions:
                # Generate unique filename
                import uuid
                filename = str(uuid.uuid4()) + '_' + file.filename
                file_path = os.path.join('uploads/teacher', filename)
                file.save(file_path)
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Insert the teacher message
        cursor.execute('''
        INSERT INTO teacher_messages (user_id, subject, message, file_path)
        VALUES (?, ?, ?, ?)
        ''', (session['user_id'], subject, message, file_path))
        conn.commit()
        
        # Get the message ID
        message_id = cursor.lastrowid
        
        # Get user email for notification
        cursor.execute('SELECT email FROM users WHERE id = ?', (session['user_id'],))
        user_email = cursor.fetchone()[0]
        
        conn.close()
        
        # Prepare message data for notification
        message_data = {
            'id': message_id,
            'user_email': user_email,
            'subject': subject,
            'message': message,
            'file_path': file_path,
            'status': 'pending',
            'user_id': session['user_id']
        }
        
        # Emit real-time notification to admin room
        socketio.emit('new_teacher_message', message_data, room='admin')
        logger.info(f"New teacher message emitted: {message_data}")
        
        return jsonify({
            'success': True, 
            'message': 'Your message has been sent to the teacher.',
            'message_id': message_id
        })
        
    except Exception as e:
        logger.error(f"Submit teacher message error: {e}")
        conn.close()
        return jsonify({'success': False, 'message': 'Failed to send message'})

@app.route('/admin/support/reply/<int:message_id>', methods=['POST'])
@admin_required
def reply_support_message(message_id):
    reply = request.form.get('reply')
    
    if not reply:
        return jsonify({'success': False, 'message': 'Reply message is required'})
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Get message details before updating
        cursor.execute('''
        SELECT sm.user_id, sm.subject, u.email
        FROM support_messages sm
        JOIN users u ON sm.user_id = u.id
        WHERE sm.id = ?
        ''', (message_id,))
        message_data = cursor.fetchone()
        
        if not message_data:
            conn.close()
            return jsonify({'success': False, 'message': 'Message not found'})
        
        # Insert reply
        cursor.execute('''
        INSERT INTO support_replies (message_id, reply)
        VALUES (?, ?)
        ''', (message_id, reply))
        
        # Update message status
        cursor.execute('UPDATE support_messages SET status = "replied" WHERE id = ?', (message_id,))
        conn.commit()
        
        # Get updated message data
        cursor.execute('''
        SELECT sm.id, u.email, sm.message_type, sm.subject, sm.message, sm.status, sm.user_id
        FROM support_messages sm
        JOIN users u ON sm.user_id = u.id
        WHERE sm.id = ?
        ''', (message_id,))
        updated_message = dict(cursor.fetchone())
        
        conn.close()
        
        # Emit real-time notification to admin room
        socketio.emit('support_message_updated', {
            'message': updated_message,
            'action': 'replied'
        }, room='admin')
        
        # Emit real-time notification to specific user
        socketio.emit('support_reply_received', {
            'message_id': message_id,
            'subject': message_data['subject'],
            'reply': reply,
            'message': f'Admin has replied to your message: "{message_data["subject"]}"'
        }, room=f"user_{message_data['user_id']}")
        
        logger.info(f"Support message {message_id} replied for user {message_data['user_id']}")
        
        return jsonify({'success': True, 'message': 'Reply sent successfully'})
        
    except Exception as e:
        logger.error(f"Reply support message error: {e}")
        conn.close()
        return jsonify({'success': False, 'message': 'Failed to send reply'})

@app.route('/admin/teacher/reply/<int:message_id>', methods=['POST'])
@admin_required
def reply_teacher_message(message_id):
    reply = request.form.get('reply')
    
    if not reply:
        return jsonify({'success': False, 'message': 'Reply message is required'})
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Get message details before updating
        cursor.execute('''
        SELECT tm.user_id, tm.subject, u.email
        FROM teacher_messages tm
        JOIN users u ON tm.user_id = u.id
        WHERE tm.id = ?
        ''', (message_id,))
        message_data = cursor.fetchone()
        
        if not message_data:
            conn.close()
            return jsonify({'success': False, 'message': 'Message not found'})
        
        # Insert reply
        cursor.execute('''
        INSERT INTO teacher_replies (message_id, reply)
        VALUES (?, ?)
        ''', (message_id, reply))
        
        # Update message status
        cursor.execute('UPDATE teacher_messages SET status = "replied" WHERE id = ?', (message_id,))
        conn.commit()
        
        # Get updated message data
        cursor.execute('''
        SELECT tm.id, u.email, tm.subject, tm.message, tm.file_path, tm.status, tm.user_id
        FROM teacher_messages tm
        JOIN users u ON tm.user_id = u.id
        WHERE tm.id = ?
        ''', (message_id,))
        updated_message = dict(cursor.fetchone())
        
        conn.close()
        
        # Emit real-time notification to admin room
        socketio.emit('teacher_message_updated', {
            'message': updated_message,
            'action': 'replied'
        }, room='admin')
        
        # Emit real-time notification to specific user
        socketio.emit('teacher_reply_received', {
            'message_id': message_id,
            'subject': message_data['subject'],
            'reply': reply,
            'message': f'Teacher has replied to your message: "{message_data["subject"]}"'
        }, room=f"user_{message_data['user_id']}")
        
        logger.info(f"Teacher message {message_id} replied for user {message_data['user_id']}")
        
        return jsonify({'success': True, 'message': 'Reply sent successfully'})
        
    except Exception as e:
        logger.error(f"Reply teacher message error: {e}")
        conn.close()
        return jsonify({'success': False, 'message': 'Failed to send reply'})

@app.route('/download/<path:filename>')
@login_required
def download_file(filename):
    try:
        return send_from_directory('uploads', filename, as_attachment=True)
    except Exception as e:
        logger.error(f"Download error: {e}")
        return jsonify({'success': False, 'message': 'File not found'}), 404

@app.route('/user/messages')
@login_required
def get_user_messages():
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Get support messages with replies
        cursor.execute('''
        SELECT sm.id, sm.subject, sm.message, sm.status, sm.created_at,
               sr.reply, sr.created_at as reply_date
        FROM support_messages sm
        LEFT JOIN support_replies sr ON sm.id = sr.message_id
        WHERE sm.user_id = ?
        ORDER BY sm.id DESC
        ''', (session['user_id'],))
        support_messages = []
        for row in cursor.fetchall():
            support_messages.append({
                'id': row['id'],
                'subject': row['subject'],
                'message': row['message'],
                'status': row['status'],
                'created_at': row['created_at'],
                'reply': row['reply'],
                'reply_date': row['reply_date']
            })
        
        # Get teacher messages with replies
        cursor.execute('''
        SELECT tm.id, tm.subject, tm.message, tm.file_path, tm.status, tm.created_at,
               tr.reply, tr.created_at as reply_date
        FROM teacher_messages tm
        LEFT JOIN teacher_replies tr ON tm.id = tr.message_id
        WHERE tm.user_id = ?
        ORDER BY tm.id DESC
        ''', (session['user_id'],))
        teacher_messages = []
        for row in cursor.fetchall():
            teacher_messages.append({
                'id': row['id'],
                'subject': row['subject'],
                'message': row['message'],
                'file_path': row['file_path'],
                'status': row['status'],
                'created_at': row['created_at'],
                'reply': row['reply'],
                'reply_date': row['reply_date']
            })
        
        conn.close()
        
        return jsonify({
            'support_messages': support_messages,
            'teacher_messages': teacher_messages
        })
        
    except Exception as e:
        logger.error(f"Get user messages error: {e}")
        conn.close()
        return jsonify({'support_messages': [], 'teacher_messages': []})

@app.route('/user/status')
def user_status():
    if 'user_id' in session:
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute('SELECT email, is_admin FROM users WHERE id = ?', (session['user_id'],))
            user = cursor.fetchone()
            conn.close()
            
            if user:
                return jsonify({
                    'logged_in': True,
                    'email': user['email'],
                    'is_admin': user['is_admin'],
                    'user_id': session['user_id']
                })
        except Exception as e:
            logger.error(f"User status error: {e}")
            conn.close()
    
    return jsonify({'logged_in': False})

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=7777, debug=True)
