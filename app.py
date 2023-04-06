from flask import Flask, render_template, request, redirect, url_for, abort
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin
import sqlite3
import bcrypt

app = Flask(__name__)
app.secret_key = 'secret'

login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id=?', (user_id,))
    user = c.fetchone()
    conn.close()
    if not user:
        return None
    return User(user[0])

# Initialize the database with a test set of accounts
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    # Check if the test accounts have already been added
    c.execute('SELECT * FROM users WHERE username="admin"')
    if not c.fetchone():
        # If not, add the test accounts
        password = b'password'
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password, salt)
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('admin', hashed_password))
        password = b'secret'
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password, salt)
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('user', hashed_password))
        conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Check if username and password are correct
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username=?', (username,))
        user = c.fetchone()
        conn.close()
        if user and bcrypt.checkpw(password.encode('utf-8'), user[2]):
            user_obj = User(user[0])
            login_user(user_obj)
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid username or password.')
    else:
        return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.errorhandler(Exception)
def handle_error(e):
    return render_template('error.html', error=str(e))

if __name__ == '__main__':
    app.run(debug=True)
