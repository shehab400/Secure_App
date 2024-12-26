from flask import Flask, render_template, request, redirect, session
import sqlite3
import html
import secrets
import logging
from functions import not_valid_input, encrypt_data, decrypt_data, is_valid_email, is_valid_password, log_suspicious_activity,hash_password
from werkzeug.security import check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Set up logging
logging.basicConfig(filename='app.log', level=logging.ERROR)

# Disable Werkzeug logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# Set up rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

def log_rate_limit_exceeded(response):
    app.logger.error("Rate limit exceeded: %s", response)
    return response

def get_user_from_db(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT username, password FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.pop('csrf_token', None)
        if not token or token != request.form.get('csrf_token'):
            app.logger.error("CSRF token missing or incorrect!")
            return "CSRF token missing or incorrect!", 400

@app.route('/home')
def home():
    message = request.args.get('message', 'Welcome!')
    return render_template('home.html', message=message)

@app.route('/comment', methods=['GET', 'POST'])
def comment():
    comments = []
    if request.method == 'POST':
        user_comment = request.form['comment']
        if "<script>" in user_comment.lower():
            log_suspicious_activity("XSS attempt", user_comment, app)
        sanitized_comment = html.escape(user_comment)
        
        with open('comments.txt', 'a') as f:
            f.write(sanitized_comment + "\n")  # Save sanitized comment to a file
        
    # Read all comments
    with open('comments.txt', 'r') as f:
        comments = f.readlines()
    
    return render_template('comments.html', comments=comments, csrf_token=generate_csrf_token())

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    success = False
    if request.method == 'POST':
        recipient = request.form['recipient']
        amount = request.form['amount']
        
        if not_valid_input(recipient) or not_valid_input(amount):
            app.logger.error("Invalid input for transfer: recipient=%s, amount=%s", recipient, amount)
            log_suspicious_activity("Invalid transfer input", f"recipient={recipient}, amount={amount}", app)
            return 'Invalid input!', 400
        
        encrepted_recipient = encrypt_data(recipient)
        encrepted_amount = encrypt_data(amount)
        
        with open('transactions.txt', 'a') as f:
            f.write(f"Transfer to: {encrepted_recipient}, Amount: {encrepted_amount}\n")
        
        success = True
    
    return render_template('transfer.html', success=success, csrf_token=generate_csrf_token())

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
    
        if not_valid_input(username) or not_valid_input(password):
            app.logger.error("Invalid input for login: username=%s", username)
            log_suspicious_activity("Invalid login input", f"username={username}", app)
            return 'Invalid input!', 400

        user = get_user_from_db(username)
        if user and check_password_hash(user[1], password):  # Compare the stored password with the provided password
            return redirect(f'/home?message=Welcome+back,+{username}') # Redirect to home page
        else:
            log_suspicious_activity("Failed login attempt", f"username={username}", app)
            return render_template('login.html', csrf_token=generate_csrf_token(), message='Incorrect password or username'), 400

    return render_template('login.html', csrf_token=generate_csrf_token(), message='')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if not_valid_input(username) or not is_valid_email(email) or not is_valid_password(password):
            app.logger.error("Invalid input for registration: username=%s, email=%s", username, email)
            log_suspicious_activity("Invalid registration input", f"username={username}, email={email}", app)
            return 'Invalid input!', 400

        if get_user_from_db(username):
            app.logger.error("User already exists: username=%s", username)
            log_suspicious_activity("Duplicate registration attempt", f"username={username}", app)
            return 'User already exists!', 400

        #use hash function to store password
        hashed_password = hash_password(password)
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        conn.close()

        return redirect('/login')

    return render_template('register.html', csrf_token=generate_csrf_token())

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    # Fetch security logs, failed login attempts, potential threats, and user activities from the log file or database
    logs = []
    failed_logins = []
    threats = []
    user_activities = []

    # Example data fetching logic (replace with actual data fetching)
    with open('app.log', 'r') as f:
        for line in f.readlines():
            parts = line.split(' ')
            if len(parts) > 2:
                timestamp = parts[0]
                event = parts[1]
                details = ' '.join(parts[2:])
                logs.append({'timestamp': timestamp, 'event': event, 'details': details})

    # Example user activity fetching logic (replace with actual data fetching)
    with open('app.log', 'r') as f:
        for line in f.readlines():
            parts = line.split(' ')
            if len(parts) > 2:
                timestamp = parts[0]
                username = parts[1]
                activity = ' '.join(parts[2:])
                user_activities.append({'timestamp': timestamp, 'username': username, 'activity': activity})

    # Render the admin dashboard template with the fetched data
    return render_template('admin_dashboard.html', logs=logs, failed_logins=failed_logins, threats=threats, user_activities=user_activities)

@app.errorhandler(400)
def bad_request_error(error):
    app.logger.error(f"Bad Request: {error}")
    return render_template('error.html', message="Bad Request!"), 400

@app.errorhandler(404)
def not_found_error(error):
    app.logger.error(f"Not Found: {error}")
    return render_template('error.html', message="Page Not Found!"), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Server Error: {error}")
    return render_template('error.html', message="Internal Server Error!"), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    app.logger.error("Rate limit exceeded: %s", e.description)
    return render_template('error.html', message="Rate limit exceeded! Please try again later."), 429


if __name__ == "__main__":
    app.run(debug=True)