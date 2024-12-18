from flask import Flask, render_template, request, redirect, session
import sqlite3
import html
import secrets

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for session management

# Insecure database connection (no parameterization)
def get_user_from_db(username):
    # Secure query using parameterized SQL
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ?"
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
            return "CSRF token missing or incorrect!", 400

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/comment', methods=['GET', 'POST'])
def comment():
    comments = []
    if request.method == 'POST':
        user_comment = request.form['comment']
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
        
        with open('transactions.txt', 'a') as f:
            f.write(f"Transfer to: {recipient}, Amount: {amount}\n")
        
        success = True
    
    return render_template('transfer.html', success=success, csrf_token=generate_csrf_token())

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = get_user_from_db(username)
        if user:
            return redirect('/home')
        else:
            return 'Invalid credentials!', 400

    return render_template('login.html', csrf_token=generate_csrf_token())

if __name__ == "__main__":
    app.run(debug=True)