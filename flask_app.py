import json
import os
from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_login import login_required
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'this_is_my_secret_key'

# Dummy storage initialization
if not os.path.exists('users.json'):
    with open('users.json', 'w') as f:
        json.dump({}, f)

def load_users():
    with open('users.json') as f:
        return json.load(f)

def save_users(users):
    with open('users.json', 'w') as f:
        json.dump(users, f)

################################# ROUTES #################################

######### LANDING ROUTE #########
@app.route('/')
def index():
    if 'user_id' in session:
        return render_template('index.html', name=session['user_name'])
    return redirect(url_for('login'))

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
        if user and user['password_hash'] == current_password:
            user['password_hash'] = new_password
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
    return redirect(url_for('index'))

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


######## MAIN TO RUN FLASK APP #########
if __name__ == '__main__':
    app.run(debug=True)
