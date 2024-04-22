import hashlib
import json
import os
from flask import Flask, Response, render_template, redirect, url_for, request, flash, session, send_from_directory
from flask_login import LoginManager, UserMixin, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
# import psycopg2
import time
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
from os import urandom
# from cryptoSite_utils import *

################################# GLOBAL #################################
app = Flask(__name__)
app.secret_key = 'this_is_my_secret_key'
app.config['MAX_CONTENT_LENGTH'] = 1024*1024
first_request = True
MAX_FILE_SIZE = 1024 * 1024

################################# DATABASE #################################
# DATABASE_URL = "postgresql://cryptosite_vs_8871_user:HSx0mek0EG4evebmrhhFluaepf35dVh4@dpg-coi3gcol5elc73d16d80-a.oregon-postgres.render.com/cryptosite_vs_8871"
user_json_file_name = "users.json"
if not os.path.exists(user_json_file_name):
    with open(user_json_file_name, 'w') as f:
        json.dump({}, f)

################################# USER #################################
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def load_users():
    with open(user_json_file_name) as f:
        return json.load(f)

def save_users(users):
    with open(user_json_file_name, 'w') as f:
        json.dump(users, f)
        
@login_manager.user_loader
def load_user(user_id):
    users = load_users()
    for user, values in users.items():
        if str(values['user_id']) == str(user_id):
            current_user = UserMixin()
            current_user.id = user.id
            return current_user
    return None

################################# SESSION #################################
@app.before_request
def clear_session():
    global first_request
    if first_request:
        session.clear()
        first_request = False

################################# ERROR HANDLING #################################
@app.errorhandler(413)
def too_large(e):
    return "Maximum file size to upload is 1 MB", 413

################################# ROUTES #################################
######### INDEX #########
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    users = load_users()
    username = session['user_name']
    user_files = users[username].get('files', [])
    return render_template('index.html', name=session['user_name'], files=user_files)

######### LOGIN #########
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        users = load_users()
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

######### REGISTER #########
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        users = load_users()
        username = request.form['username']
        if username in users:
            flash('Username already taken.')
            return render_template('register.html')
        
        password = request.form['password']
        name = request.form['name']
        user_id = len(users) + 1
        users[username] = {
            'id': user_id,
            'name': name,
            'password_hash': generate_password_hash(password)
        }
        save_users(users)
        flash('You have successfully registered!')
        return redirect(url_for('login'))
    return render_template('register.html')

######### MODIFY PWD #########
@app.route('/modify_pwd', methods=['GET', 'POST'])
def modify_pwd():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        users = load_users()
        username = session['user_name']
        user = users.get(username)
        
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        if user and check_password_hash(user['password_hash'], current_password):
            user['password_hash'] = generate_password_hash(new_password)
            save_users(users)
            flash('Password successfully modified!')
            return redirect(url_for('index'))
        flash('Current password is incorrect.')
    return render_template('modify_password.html')

######### LOGOUT #########
@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    session.pop('user_name', None)
    return redirect(url_for('login'))

######### DELETE USR #########
@app.route('/delete_account')
def delete_account():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    users = load_users()
    username = session['user_name']
    if username in users:
        del users[username]
        save_users(users)
        session.pop('user_id', None)
        session.pop('user_name', None)
        flash('Account deleted successfully.')
    return redirect(url_for('login'))

######### UPLOAD FILES #########
@app.route('/upload_file', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file:
            filename = secure_filename(file.filename)
            users = load_users()
            username = session['user_name']
            user_dir = os.path.join('uploads', username + '_uploads')
            os.makedirs(user_dir, exist_ok=True)  # Create directory if it does not exist
            filepath = os.path.join(user_dir, filename)
            # if not os.path.getsize(file)/MAX_FILE_SIZE < 1:
            #     flash('Maximum file size is 1 MB.')
            #     return redirect(request.url)
            file.save(filepath)
            user_files = users[username].get('files', [])
            if len(user_files) >= 8:
                flash('Maximum number of files reached.')
                return redirect(request.url)
            user_files.append({'filename': filename, 'path': filepath})  # Store filename and path
            users[username]['files'] = user_files
            save_users(users)
            flash('File successfully uploaded.')
            return redirect(url_for('index'))
    return render_template('upload_file.html')

######### DOWNLAOD FILES #########
@app.route('/download_file/<filename>')
def download_file(filename):
    username = session['user_name']
    users = load_users()
    user_files = users[username].get('files', [])
    file_info = next((file for file in user_files if file['filename'] == filename), None)
    if file_info:
        file_path = file_info['path']
        directory, filename = os.path.split(file_path)
        return send_from_directory(directory, filename, as_attachment=True)
    else:
        flash('File not found.')
        return redirect(url_for('index'))

######### DEL FILES #########
@app.route('/delete_file/<filename>')
def delete_file(filename):
    username = session['user_name']
    users = load_users()
    user_files = users[username].get('files', [])
    file_info = next((file for file in user_files if file['filename'] == filename), None)
    if file_info:
        os.remove(file_info['path'])  
        users[username]['files'] = [file for file in user_files if file['filename'] != filename] 
        save_users(users)
        flash('File deleted successfully.')
        return redirect(url_for('index'))
    else:
        flash('File not found.')
        return redirect(url_for('index'))

######### KEY GEN #########
@app.route('/generate_key', methods=['GET'])
def generate_key():
    start_time = time.time()
    keys = [Fernet.generate_key().decode() for _ in range(20)]
    elapsed_time = time.time() - start_time
    flash(f'Key generated in {elapsed_time:.6f} seconds.')
    return render_template('display_keys.html', keys=keys)

######### HASHING #########
@app.route('/hash_file/<filename>', methods=['GET'])
def hash_file(filename):
    start_time = time.time()
    username = session['user_name']
    users = load_users()
    user_files = users[username].get('files', [])
    file_info = next((file for file in user_files if file['filename'] == filename), None)

    if not file_info:
        flash('File not found.')
        return redirect(url_for('index'))

    file_path = file_info['path']
    with open(file_path, 'rb') as f:
        file_data = f.read()

    sha256_hash = hashlib.sha256(file_data).hexdigest()
    md5_hash = hashlib.md5(file_data).hexdigest()

    # Save hashes to file metadata
    file_info['sha256'] = sha256_hash
    file_info['md5'] = md5_hash
    save_users(users)

    elapsed_time = time.time() - start_time
    flash(f'File hashed in {elapsed_time:.6f} seconds. SHA256: {sha256_hash}, MD5: {md5_hash}')
    return redirect(url_for('index'))

######### DOWNLOAD HASH RES #########
@app.route('/download_hash/<filename>', methods=['GET'])
def download_hash(filename):
    username = session['user_name']
    users = load_users()
    user_files = users[username].get('files', [])
    file_info = next((file for file in user_files if file['filename'] == filename), None)

    if not file_info or 'sha256' not in file_info or 'md5' not in file_info:
        flash('Hashes not found. Please hash the file first.')
        return redirect(url_for('index'))

    hash_content = f"SHA256: {file_info['sha256']}\nMD5: {file_info['md5']}"
    return Response(
        hash_content,
        mimetype="text/plain",
        headers={"Content-disposition": "attachment; filename=hashes.txt"})

######### ENCRYPTION #########
@app.route('/encrypt_file/<filename>', methods=['GET', 'POST'])
def encrypt_file(filename):
    start_time = time.time()
    username = session['user_name']
    users = load_users()
    user_files = users[username].get('files', [])
    file_info = next((file for file in user_files if file['filename'] == filename), None)
    
    if not file_info:
        flash('File not found.')
        return redirect(url_for('index'))

    file_path = file_info['path']
    with open(file_path, 'rb') as f:
        data = f.read()

    encryption_method = request.form.get('encryption_method')
    if not encryption_method:
        flash('No encryption method selected.')
        return redirect(url_for('index'))

    if encryption_method == 'AES-192':
        key = urandom(24)
        iv = urandom(16)
        algorithm = algorithms.AES(key)
    elif encryption_method == 'Blowfish':
        key = urandom(16)
        iv = urandom(8)
        algorithm = algorithms.Blowfish(key)
    else:
        flash('Invalid encryption method.')
        return redirect(url_for('index'))

    cipher = Cipher(algorithm, modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithm.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # encrypted_file_path = file_path + '.encrypted'
    with open(file_path, 'wb') as f:
        f.write(encrypted_data)

    # Save key and IV for later decryption
    # file_info['filename'] = filename + '.encrypted'
    file_info['encrypted'] = True
    file_info['key'] = key.hex()
    file_info['iv'] = iv.hex()
    file_info['method'] = encryption_method
    save_users(users)

    elapsed_time = time.time() - start_time
    flash(f'File encrypted using {encryption_method} in {elapsed_time:.6f} seconds.')
    return redirect(url_for('index'))

######### DECRYPT #########
@app.route('/decrypt_file/<filename>', methods=['GET', 'POST'])
def decrypt_file(filename):
    start_time = time.time()
    username = session['user_name']
    users = load_users()
    user_files = users[username].get('files', [])
    
    # file_info = next((file for file in user_files if file['filename'] == filename), None)
    file_info = next((file for file in user_files if file['filename'] == filename and file.get('encrypted')), None)
    
    if not file_info:
        flash('Encrypted file not found.')
        return redirect(url_for('index'))
    
    file_path = file_info['path']
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    key = bytes.fromhex(file_info['key'])
    iv = bytes.fromhex(file_info['iv'])
    encryption_method = file_info.get('method')

    if encryption_method == 'AES-192':
        algorithm = algorithms.AES(key)
    elif encryption_method == 'Blowfish':
        algorithm = algorithms.Blowfish(key)
    else:
        flash('Encryption method not supported for decryption.')
        return redirect(url_for('index'))

    cipher = Cipher(algorithm, modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithm.block_size).unpadder()
    data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    # decrypted_file_path = file_path.removesuffix('.encrypted')
    with open(file_path, 'wb') as f:
        f.write(data)
    
    file_info.pop('encrypted', None)
    file_info.pop('key', None)
    file_info.pop('iv', None)
    file_info.pop('method', None)
    save_users(users)

    elapsed_time = time.time() - start_time
    flash(f'File decrypted in {elapsed_time:.6f} seconds.')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
