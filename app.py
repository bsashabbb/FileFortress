from flask import Flask, render_template_string, request, session, redirect, url_for, flash, abort, send_file
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import sqlite3
from dotenv import load_dotenv
import os
import time
import threading
import re
from io import BytesIO
from werkzeug.exceptions import RequestEntityTooLarge
import uuid

def generate_unique_filename(filename):
    # Получаем расширение файла
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    # Генерируем уникальное имя с использованием UUID
    unique_name = str(uuid.uuid4())
    # Возвращаем имя с расширением, если оно было
    return f"{unique_name}.{ext}" if ext else unique_name

# Загрузка переменных окружения
load_dotenv()

# Функция для генерации и сохранения ключей
def generate_and_save_keys():
    # Генерация ключей
    secret_key = os.urandom(24).hex()  # Секретный ключ для Flask
    fernet_key = Fernet.generate_key().decode()  # Ключ для Fernet

    # Сохранение ключей в .env файл
    with open('.env', 'w') as f:
        f.write(f"SECRET_KEY={secret_key}\n")
        f.write(f"FERNET_KEY={fernet_key}\n")

    return secret_key, fernet_key

# Проверка наличия ключей
if not os.path.exists('.env'):
    print("Файл .env не найден. Генерация новых ключей...")
    secret_key, fernet_key = generate_and_save_keys()
else:
    # Загрузка ключей из .env
    secret_key = os.getenv('SECRET_KEY')
    fernet_key = os.getenv('FERNET_KEY')

    # Если ключи отсутствуют в .env, генерируем их
    if not secret_key or not fernet_key:
        print("Ключи отсутствуют в .env. Генерация новых ключей...")
        secret_key, fernet_key = generate_and_save_keys()

# Инициализация Flask
app = Flask(__name__)

# Конфигурация
app.secret_key = secret_key  # Секретный ключ для Flask
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_FILE_SIZE'] = 10 * 1024 * 1024  # 10 МБ
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}  # Разрешенные расширения
app.config['DATABASE'] = 'database.db'
app.config['MAX_FILE_AGE'] = 600  # 10 минут в секундах
app.config['PASSWORD_MIN_LENGTH'] = 12  # Минимальная длина пароля
app.config['PASSWORD_COMPLEXITY'] = {
    'uppercase': 1,  # Минимум 1 заглавная буква
    'lowercase': 1,  # Минимум 1 строчная буква
    'digits': 1,     # Минимум 1 цифра
    'special': 1     # Минимум 1 специальный символ
}

# Инициализация Fernet
cipher_suite = Fernet(fernet_key.encode())  # Секретный ключ для Fernet

# Инициализация CSRF-защиты
csrf = CSRFProtect(app)

# Инициализация Talisman для безопасности
Talisman(
    app,
    force_https=False,  # Отключить принудительное HTTPS
    strict_transport_security=False,  # Отключить HSTS
    content_security_policy=None,  # Отключить CSP
    referrer_policy='no-referrer'  # Отключить проверку Referer
)

# Инициализация Limiter для ограничения запросов
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Подключение к базе данных
def get_db():
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    return db

# Инициализация базы данных
def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                failed_login_attempts INTEGER DEFAULT 0,
                last_failed_login REAL DEFAULT 0
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                upload_time REAL NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        db.commit()

# Проверка сложности пароля
def is_password_complex(password):
    if len(password) < app.config['PASSWORD_MIN_LENGTH']:
        return False
    complexity = app.config['PASSWORD_COMPLEXITY']
    if complexity['uppercase'] and not re.search(r'[A-Z]', password):
        return False
    if complexity['lowercase'] and not re.search(r'[a-z]', password):
        return False
    if complexity['digits'] and not re.search(r'[0-9]', password):
        return False
    if complexity['special'] and not re.search(r'[^A-Za-z0-9]', password):
        return False
    return True

# Удаление старых файлов
def delete_old_files():
    while True:
        time.sleep(60)  # Проверка каждую минуту
        with app.app_context():
            db = get_db()
            current_time = time.time()
            old_files = db.execute('''
                SELECT id, filename FROM files WHERE ? - upload_time > ?
            ''', (current_time, app.config['MAX_FILE_AGE'])).fetchall()
            for file in old_files:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], file['filename'])
                if os.path.exists(file_path):
                    os.remove(file_path)
                db.execute('DELETE FROM files WHERE id = ?', (file['id'],))
            db.commit()

# Запуск фоновой задачи для удаления файлов
threading.Thread(target=delete_old_files, daemon=True).start()

# Обработка ошибки превышения размера файла
@app.errorhandler(RequestEntityTooLarge)
def handle_large_file(e):
    flash('File size exceeds the maximum allowed limit of 10 MB.', 'error')
    return redirect(url_for('upload_file'))

# Главная страница
@app.route('/')
def index():
    return render_template_string('''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Secure Flask App</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f9;
                    color: #333;
                    margin: 0;
                    padding: 0;
                }
                .container {
                    max-width: 800px;
                    margin: 50px auto;
                    padding: 20px;
                    background: #fff;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                    border-radius: 8px;
                }
                h1 {
                    color: #007BFF;
                    text-align: center;
                }
                .nav {
                    display: flex;
                    justify-content: center;
                    margin-bottom: 20px;
                }
                .nav a {
                    margin: 0 15px;
                    text-decoration: none;
                    color: #007BFF;
                    font-weight: bold;
                }
                .nav a:hover {
                    text-decoration: underline;
                }
                .flash {
                    padding: 10px;
                    margin: 10px 0;
                    border-radius: 5px;
                    text-align: center;
                }
                .flash.success {
                    background-color: #d4edda;
                    color: #155724;
                }
                .flash.error {
                    background-color: #f8d7da;
                    color: #721c24;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Welcome to the Secure Flask App</h1>
                <div class="nav">
                    <a href="/">Home</a>
                    <a href="/login">Login</a>
                    <a href="/register">Register</a>
                    <a href="/upload">Upload</a>
                    <a href="/profile">Profile</a>
                </div>
                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% for category, message in messages %}
                            <div class="flash {{ category }}">{{ message }}</div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
            </div>
        </body>
        </html>
    ''')

# Регистрация
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username and password:
            if not is_password_complex(password):
                flash('Password must be at least 12 characters long and include uppercase, lowercase, digits, and special characters.', 'error')
                return redirect(url_for('register'))
            db = get_db()
            try:
                hashed_password = generate_password_hash(password)
                db.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                           (username, hashed_password))
                db.commit()
                flash('Registration successful! Please login.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Username already exists.', 'error')
        else:
            flash('Please fill out all fields.', 'error')
    return render_template_string('''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Register</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f9;
                    color: #333;
                    margin: 0;
                    padding: 0;
                }
                .container {
                    max-width: 800px;
                    margin: 50px auto;
                    padding: 20px;
                    background: #fff;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                    border-radius: 8px;
                }
                h1 {
                    color: #007BFF;
                    text-align: center;
                }
                .flash {
                    padding: 10px;
                    margin: 10px 0;
                    border-radius: 5px;
                    text-align: center;
                }
                .flash.success {
                    background-color: #d4edda;
                    color: #155724;
                }
                .flash.error {
                    background-color: #f8d7da;
                    color: #721c24;
                }
                form {
                    display: flex;
                    flex-direction: column;
                    gap: 10px;
                }
                form input, form button {
                    padding: 10px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    font-size: 16px;
                }
                form button {
                    background-color: #007BFF;
                    color: #fff;
                    cursor: pointer;
                }
                form button:hover {
                    background-color: #0056b3;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Register</h1>
                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% for category, message in messages %}
                            <div class="flash {{ category }}">{{ message }}</div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                    <button type="submit">Register</button>
                </form>
            </div>
        </body>
        </html>
    ''')

# Вход
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Ограничение попыток входа
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username and password:
            db = get_db()
            user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            if user:
                # Проверка блокировки аккаунта
                if user['failed_login_attempts'] >= 5 and (time.time() - user['last_failed_login']) < 300:
                    flash('Account locked. Try again later.', 'error')
                    return redirect(url_for('login'))
                if check_password_hash(user['password'], password):
                    # Сброс счетчика неудачных попыток
                    db.execute('UPDATE users SET failed_login_attempts = 0 WHERE id = ?', (user['id'],))
                    db.commit()
                    session['user_id'] = user['id']
                    flash('Login successful!', 'success')
                    return redirect(url_for('profile'))
                else:
                    # Увеличение счетчика неудачных попыток
                    db.execute('UPDATE users SET failed_login_attempts = failed_login_attempts + 1, last_failed_login = ? WHERE id = ?',
                               (time.time(), user['id']))
                    db.commit()
                    flash('Invalid username or password.', 'error')
            else:
                flash('Invalid username or password.', 'error')
        else:
            flash('Please fill out all fields.', 'error')
    return render_template_string('''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Login</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f9;
                    color: #333;
                    margin: 0;
                    padding: 0;
                }
                .container {
                    max-width: 800px;
                    margin: 50px auto;
                    padding: 20px;
                    background: #fff;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                    border-radius: 8px;
                }
                h1 {
                    color: #007BFF;
                    text-align: center;
                }
                .flash {
                    padding: 10px;
                    margin: 10px 0;
                    border-radius: 5px;
                    text-align: center;
                }
                .flash.success {
                    background-color: #d4edda;
                    color: #155724;
                }
                .flash.error {
                    background-color: #f8d7da;
                    color: #721c24;
                }
                form {
                    display: flex;
                    flex-direction: column;
                    gap: 10px;
                }
                form input, form button {
                    padding: 10px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    font-size: 16px;
                }
                form button {
                    background-color: #007BFF;
                    color: #fff;
                    cursor: pointer;
                }
                form button:hover {
                    background-color: #0056b3;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Login</h1>
                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% for category, message in messages %}
                            <div class="flash {{ category }}">{{ message }}</div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                    <button type="submit">Login</button>
                </form>
            </div>
        </body>
        </html>
    ''')

# Профиль
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Please login to view your profile.', 'error')
        return redirect(url_for('login'))

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    files = db.execute('SELECT * FROM files WHERE user_id = ?', (session['user_id'],)).fetchall()

    return render_template_string('''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Profile</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f9;
                    color: #333;
                    margin: 0;
                    padding: 0;
                }
                .container {
                    max-width: 800px;
                    margin: 50px auto;
                    padding: 20px;
                    background: #fff;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                    border-radius: 8px;
                }
                h1 {
                    color: #007BFF;
                    text-align: center;
                }
                .flash {
                    padding: 10px;
                    margin: 10px 0;
                    border-radius: 5px;
                    text-align: center;
                }
                .flash.success {
                    background-color: #d4edda;
                    color: #155724;
                }
                .flash.error {
                    background-color: #f8d7da;
                    color: #721c24;
                }
                .file-list {
                    list-style-type: none;
                    padding: 0;
                }
                .file-list li {
                    padding: 10px;
                    border-bottom: 1px solid #ddd;
                }
                .file-list li:last-child {
                    border-bottom: none;
                }
                a {
                    color: #007BFF;
                    text-decoration: none;
                }
                a:hover {
                    text-decoration: underline;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Profile</h1>
                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% for category, message in messages %}
                            <div class="flash {{ category }}">{{ message }}</div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
                <p>Welcome, {{ user.username }}!</p>
                <h2>Your Files</h2>
                <ul class="file-list">
                    {% for file in files %}
                        <li>
                            {{ file.filename }} - 
                            <a href="/download/{{ file.filename }}">Download</a>
                        </li>
                    {% endfor %}
                </ul>
                <a href="/upload">Upload a file</a>
                <br>
                <a href="/logout">Logout</a>
            </div>
        </body>
        </html>
    ''', user=user, files=files)

# Загрузка файла
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'user_id' not in session:
        flash('Please login to upload files.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Проверка наличия файла в запросе
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)

        file = request.files['file']

        # Если пользователь не выбрал файл
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)

        # Проверка размера файла
        file.seek(0, os.SEEK_END)  # Перемещаем указатель в конец файла
        file_size = file.tell()  # Получаем размер файла
        file.seek(0)  # Возвращаем указатель в начало файла

        if file_size > app.config['MAX_FILE_SIZE']:
            flash('File size exceeds the maximum allowed limit of 10 MB.', 'error')
            return redirect(request.url)

        # Генерация уникального имени файла с сохранением расширения
        filename = generate_unique_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Чтение и шифрование файла
        file_data = file.read()
        encrypted_data = cipher_suite.encrypt(file_data)

        # Сохранение зашифрованного файла
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)

        # Сохранение информации о файле в базе данных
        db = get_db()
        db.execute('INSERT INTO files (user_id, filename, upload_time) VALUES (?, ?, ?)',
                   (session['user_id'], filename, time.time()))
        db.commit()

        flash('File successfully uploaded', 'success')
        return redirect(url_for('profile'))

    return render_template_string('''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Upload File</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f9;
                    color: #333;
                    margin: 0;
                    padding: 0;
                }
                .container {
                    max-width: 800px;
                    margin: 50px auto;
                    padding: 20px;
                    background: #fff;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                    border-radius: 8px;
                }
                h1 {
                    color: #007BFF;
                    text-align: center;
                }
                .flash {
                    padding: 10px;
                    margin: 10px 0;
                    border-radius: 5px;
                    text-align: center;
                }
                .flash.success {
                    background-color: #d4edda;
                    color: #155724;
                }
                .flash.error {
                    background-color: #f8d7da;
                    color: #721c24;
                }
                form {
                    display: flex;
                    flex-direction: column;
                    gap: 10px;
                }
                form input, form button {
                    padding: 10px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    font-size: 16px;
                }
                form button {
                    background-color: #007BFF;
                    color: #fff;
                    cursor: pointer;
                }
                form button:hover {
                    background-color: #0056b3;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Upload File</h1>
                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% for category, message in messages %}
                            <div class="flash {{ category }}">{{ message }}</div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
                <form method="POST" enctype="multipart/form-data">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                    <label for="file">Choose file:</label>
                    <input type="file" id="file" name="file" required>
                    <button type="submit">Upload</button>
                </form>
            </div>
        </body>
        </html>
    ''')

# Скачивание файла
@app.route('/download/<filename>')
def download(filename):
    if 'user_id' not in session:
        flash('Please login to download files.', 'error')
        return redirect(url_for('login'))

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(file_path):
        abort(404)

    # Чтение и расшифровка файла
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = cipher_suite.decrypt(encrypted_data)

    # Отправка расшифрованного файла пользователю
    return send_file(
        BytesIO(decrypted_data),
        as_attachment=True,
        download_name=filename
    )

# Выход
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

# Запуск приложения
if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    init_db()
    app.run(host='0.0.0.0', port=5000)