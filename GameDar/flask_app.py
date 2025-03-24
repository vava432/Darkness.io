from flask import Flask, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
socketio = SocketIO(app)

def init_db():
    conn = sqlite3.connect('wep.db')
    cursor = conn.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, is_admin INTEGER DEFAULT 0)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS suggestions (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, suggestion TEXT NOT NULL, contact TEXT, timestamp TEXT)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, message TEXT NOT NULL, timestamp TEXT)""")
    conn.commit()

    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        admin_password = generate_password_hash('WEPDARqwe', method='pbkdf2:sha256')
        cursor.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)", ('Va_Dar', admin_password, 1))
        conn.commit()

    conn.close()

with app.app_context():
    init_db()

def is_admin(username):
    conn = sqlite3.connect('wep.db')
    cursor = conn.cursor()
    cursor.execute("SELECT is_admin FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    return result and result[0] == 1

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        try:
            conn = sqlite3.connect('wep.db')
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
            conn.commit()
            session['username'] = username
            return redirect(url_for('glav'))
        except sqlite3.IntegrityError:
            return render_template('log.html', register=True, error="Имя пользователя уже существует")
        finally:
            conn.close()
    return render_template('log.html', register=True)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('wep.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('glav'))
        else:
            return render_template('log.html', register=False, error="Неверное имя пользователя или пароль. Если вы забыли пароль, обратитесь к администратору.")
    return render_template('log.html', register=False)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route("/")
def glav():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    admin = is_admin(username)
    return render_template('glav.html', username=username, admin=admin)

@app.route('/pred', methods=['GET', 'POST'])
def pred():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        suggestion = request.form['suggestion']
        contact = request.form['contact']
        username = session['username']
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn = sqlite3.connect('wep.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO suggestions (username, suggestion, contact, timestamp) VALUES (?, ?, ?, ?)", (username, suggestion, contact, timestamp))
        conn.commit()
        conn.close()
        return redirect(url_for('glav'))

    return render_template('pred.html')

@app.route('/delete_suggestion/<int:id>')
def delete_suggestion(id):
    conn = sqlite3.connect('wep.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM suggestions WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('glav'))

@app.route('/suggestions')
def suggestions():
    conn = sqlite3.connect('wep.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, suggestion, contact, timestamp FROM suggestions")
    suggestions = cursor.fetchall()
    conn.close()
    return render_template('suggestions.html', suggestions=suggestions)

@app.route('/add_admin', methods=['GET', 'POST'])
def add_admin():
    if 'username' not in session or not is_admin(session['username']):
        return "У вас нет прав для добавления администратора"

    if request.method == 'POST':
        new_admin_username = request.form['username']
        conn = sqlite3.connect('wep.db')
        cursor = conn.cursor()
        try:
            cursor.execute("UPDATE users SET is_admin = 1 WHERE username = ?", (new_admin_username,))
            conn.commit()
            return render_template('add_admin.html')
        except:
            return render_template('add_admin.html')
        finally:
            conn.close()

    return render_template('add_admin.html')

@app.route('/prof')
def prof():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    conn = sqlite3.connect('wep.db')
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return "User not found", 404

    user_info = {
        'username': user[0],
    }

    return render_template('prof.html', user=user_info)

@app.route('/change_password', methods=['POST'])
def change_password():
    if 'username' not in session:
        return redirect(url_for('login'))

    current_password = request.form['current_password']
    new_password = request.form['new_password']
    username = session['username']

    conn = sqlite3.connect('wep.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user[0], current_password):
        password_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
        conn = sqlite3.connect('wep.db')
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password_hash = ? WHERE username = ?", (password_hash, username))
        conn.commit()
        conn.close()
        return "Пароль успешно изменен"
    else:
        return "Текущий пароль неверен"

@app.route('/change_username', methods=['POST'])
def change_username():
    if 'username' not in session:
        return redirect(url_for('login'))

    new_username = request.form['new_username']
    username = session['username']

    conn = sqlite3.connect('wep.db')
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET username = ? WHERE username = ?", (new_username, username))
        conn.commit()
        session['username'] = new_username
        return "Имя пользователя успешно изменено"
    except sqlite3.IntegrityError:
        return "Имя пользователя уже существует"
    finally:
        conn.close()

@app.route('/admin')
def admin():
    if 'username' not in session or not is_admin(session['username']):
        return "У вас нет прав для доступа к этой странице"

    conn = sqlite3.connect('wep.db')
    cursor = conn.cursor()
    cursor.execute("SELECT username, is_admin FROM users")
    users = cursor.fetchall()
    conn.close()

    return render_template('admin.html', users=users)

@app.route('/delete_user', methods=['POST'])
def delete_user():
    if 'username' not in session or not is_admin(session['username']):
        return "У вас нет прав для выполнения этой операции"

    username_to_delete = request.form['username']

    conn = sqlite3.connect('wep.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE username=?", (username_to_delete,))
    conn.commit()
    conn.close()

    return redirect('/admin')

@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('wep.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, message, timestamp FROM messages ORDER BY timestamp")
    messages = cursor.fetchall()
    conn.close()
    admin = is_admin(session['username'])
    return render_template('chat.html', messages=messages, username=session['username'], admin=admin)

@socketio.on('send_message')
def handle_message(data):
    username = session['username']
    message = data['message']
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    conn = sqlite3.connect('wep.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO messages (username, message, timestamp) VALUES (?, ?, ?)", (username, message, timestamp))
    message_id = cursor.lastrowid
    conn.commit()
    conn.close()

    emit('new_message', {
        'id': message_id,
        'username': username,
        'message': message,
        'timestamp': timestamp
    }, broadcast=True)

@app.route('/delete_message/<int:id>')
def delete_message(id):
    if 'username' not in session or not is_admin(session['username']):
        return "У вас нет прав для удаления сообщений"

    conn = sqlite3.connect('wep.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM messages WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    return render_template('chat.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)