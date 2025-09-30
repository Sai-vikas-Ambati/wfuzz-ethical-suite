#!/usr/bin/env python3
"""
Vulnerable Web Application for Educational Security Testing
This application intentionally contains security vulnerabilities for educational purposes.
DO NOT deploy this in production environments.
"""

from flask import Flask, request, render_template_string, redirect, session, jsonify
import os
import time
import logging
from functools import wraps
import hashlib
import sqlite3
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'vulnerable_secret_key'  # Intentionally weak

# Configure logging for attack detection
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_log.txt'),
        logging.StreamHandler()
    ]
)

# Rate limiting dictionary (simple in-memory store)
request_counts = {}
blocked_ips = {}

# Initialize database
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user'
        )
    ''')
    
    # Insert test users
    test_users = [
        ('admin', 'admin123', 'admin'),
        ('user1', 'password', 'user'),
        ('test', 'test123', 'user'),
        ('guest', 'guest', 'user')
    ]
    
    for username, password, role in test_users:
        cursor.execute('INSERT OR IGNORE INTO users VALUES (NULL, ?, ?, ?)', 
                      (username, password, role))
    
    conn.commit()
    conn.close()

# Rate limiting decorator for Brute force
def rate_limit(max_requests=10, window_seconds=60):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.remote_addr
            current_time = time.time()
            
            # Check if IP is blocked
            if client_ip in blocked_ips:
                if current_time < blocked_ips[client_ip]:
                    logging.warning(f"Blocked IP {client_ip} attempted access")
                    return jsonify({'error': 'IP temporarily blocked due to suspicious activities'}), 429
                else:
                    del blocked_ips[client_ip]
            
            # Initialize or clean old requests.
            if client_ip not in request_counts:
                request_counts[client_ip] = []
            
            request_counts[client_ip] = [
                req_time for req_time in request_counts[client_ip] 
                if current_time - req_time < window_seconds
            ]
            
            # Check rate limit
            if len(request_counts[client_ip]) >= max_requests:
                # Block IP for 5 minutes
                blocked_ips[client_ip] = current_time + 300
                logging.warning(f"Rate limit exceeded for IP {client_ip}. Blocking for 5 minutes.")
                return jsonify({'error': 'Rate limit exceeded. Try again later.'}), 429
            
            request_counts[client_ip].append(current_time)
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

#  SQL Injection Prevention Vulnerable login endpoint (for demonstration)
@app.route('/vulnerable_login', methods=['GET', 'POST'])
def vulnerable_login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Log login attempt
        logging.info(f"Login attempt for username: {username} from IP: {request.remote_addr}")
        
        # Vulnerable SQL query 
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # This is intentionally vulnerable to SQL injection
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        logging.info(f"Executing query: {query}")
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            conn.close()
            
            if user:
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['role'] = user[3]
                return jsonify({'status': 'success', 'message': f'Welcome {username}!'})
            else:
                return jsonify({'status': 'error', 'message': 'Invalid credentials'})
        except Exception as e:
            conn.close()
            logging.error(f"Database error: {str(e)}")
            return jsonify({'status': 'error', 'message': 'Database error'})
    
    return '''
    <form method="post">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    '''

# Secure SQL injection login endpoint with countermeasures
@app.route('/secure_login', methods=['GET', 'POST'])
@rate_limit(max_requests=5, window_seconds=300)  # 5 attempts per 5 minutes
def secure_login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Input validation
        if not username or not password:
            return jsonify({'status': 'error', 'message': 'Username and password required'})
        
        if len(username) > 50 or len(password) > 100:
            return jsonify({'status': 'error', 'message': 'Input too long'})
        
        # Log secure login attempt
        logging.info(f"Secure login  attempt for username: {username} from IP: {request.remote_addr}")
        
        # Secure parameterized query
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = cursor.fetchone()
        conn.close()
        
        # Add delay to prevent timing attacks
        time.sleep(1)
        
        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[3]
            return jsonify({'status': 'success', 'message': f'Welcome {username}!'})
        else:
            logging.warning(f"Failed login attempt for username: {username} from IP: {request.remote_addr}")
            return jsonify({'status': 'error', 'message': 'Invalid credentials'})
    
    return '''
    <form method="post">
        Username: <input type="text" name="username" maxlength="50"><br>
        Password: <input type="password" name="password" maxlength="100"><br>
        <input type="submit" value="Login">
    </form>
    '''

# Directory traversal vulnerability
@app.route('/files/<path:filename>')
def vulnerable_file_access(filename):
    try:
        # Vulnerable: allows directory traversal
        with open(filename, 'r') as f:
            content = f.read()
        return f'<pre>{content}</pre>'
    except:
        return 'File not found', 404

# Secure file access
@app.route('/secure_files/<filename>')
def secure_file_access(filename):
    # Whitelist allowed files
    allowed_files = ['readme.txt', 'info.txt', 'help.txt']
    
    if filename not in allowed_files:
        logging.warning(f"Unauthorized file access attempt: {filename} from IP: {request.remote_addr}")
        return 'Access denied', 403
    
    safe_path = os.path.join('safe_files', filename)
    if not os.path.exists(safe_path):
        return 'File not found', 404
    
    try:
        with open(safe_path, 'r') as f:
            content = f.read()
        return f'<pre>{content}</pre>'
    except:
        return 'Error reading file', 500

# XSS Search functionality vulnerable 
@app.route('/search')
def vulnerable_search():
    query = request.args.get('q', '')
    # Vulnerable: reflects user input without sanitization
    return f'<h2>Search results for: {query}</h2><p>No results found.</p>'

# Secure search with XSS protection
@app.route('/secure_search')
def secure_search():
    from html import escape
    query = request.args.get('q', '').strip()
    
    if len(query) > 100:
        return 'Search query too long', 400
    
    # Sanitize output
    safe_query = escape(query)
    return f'<h2>Search results for: {safe_query}</h2><p>No results found.</p>'

# Admin panel with weak authentication
@app.route('/admin')
def admin_panel():
    if 'role' in session and session['role'] == 'admin':
        return '<h1>Admin Panel</h1><p>Welcome to the admin area!</p>'
    return 'Access denied', 403

# Create test directories and files
def create_test_environment():
    os.makedirs('safe_files', exist_ok=True)
    
    # Create safe files
    with open('safe_files/readme.txt', 'w') as f:
        f.write('This is a safe readme file.')
    
    with open('safe_files/info.txt', 'w') as f:
        f.write('Application information file.')
    
    # Create a sensitive file (for demonstration)
    with open('sensitive_config.txt', 'w') as f:
        f.write('SECRET_KEY=super_secret_password\nDB_PASSWORD=admin123')

@app.route('/')
def index():
    return '''
    <h1>Security Testing Web Application</h1>
    <h2>Vulnerable Endpoints (for testing):</h2>
    <ul>
        <li><a href="/vulnerable_login">Vulnerable Login</a></li>
        <li><a href="/files/sensitive_config.txt">File Access (try: ../etc/passwd)</a></li>
        <li><a href="/search?q=<script>alert('XSS')</script>">Search with XSS</a></li>
    </ul>
    
    <h2>Secure Endpoints:</h2>
    <ul>
        <li><a href="/secure_login">Secure Login</a></li>
        <li><a href="/secure_files/readme.txt">Secure File Access</a></li>
        <li><a href="/secure_search?q=test">Secure Search</a></li>
    </ul>
    '''

if __name__ == '__main__':
    init_db()
    create_test_environment()
    print("Starting vulnerable web application for educational purposes...")
    print("Access at: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)