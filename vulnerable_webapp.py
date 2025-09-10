#!/usr/bin/env python3
"""
Vulnerable Web Application for Educational Security Testing
This application intentionally contains security vulnerabilities. 
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

# Configure logging for attack detection with all logs in one file
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_log.txt'),
        logging.StreamHandler()
    ]
)

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

if __name__ == '__main__':
    init_db()
    print("Database initialized...")
    app.run(debug=True, host='0.0.0.0', port=5000)
