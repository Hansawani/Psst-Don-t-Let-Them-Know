from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from bson.objectid import ObjectId

import os

# Check if key exists, if not generate a new one and save it to a file
def load_key():
    if os.path.exists("encryption.key"):
        with open("encryption.key", "rb") as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        with open("encryption.key", "wb") as key_file:
            key_file.write(key)
        return key

# Load the key when the app starts
key = load_key()
cipher_suite = Fernet(key)

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Use environment variable for production

# MongoDB Config
app.config["MONGO_URI"] = "mongodb+srv://sushwetabm:3rBSUozWnq6nvNEl@cluster0.2ncb4.mongodb.net/test?retryWrites=true&w=majority"
mongo = PyMongo(app)

# Debugging: Check MongoDB connection
if not mongo.cx:
    raise Exception("MongoDB connection failed. Check your MONGO_URI configuration.")

# Flask-Login Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# User class for Flask-Login integration
class User(UserMixin):
    def __init__(self, id, username, email):
        self.id = str(id)  # User id needs to be a string, MongoDB's ObjectId is not a string
        self.username = username
        self.email = email

    def __repr__(self):
        return f'<User {self.username}>'


# User loader function
@login_manager.user_loader
def load_user(user_id):
    users = mongo.db.users
    user_data = users.find_one({"_id": ObjectId(user_id)})
    if user_data:
        return User(str(user_data["_id"]), user_data["username"], user_data["email"])
    return None


# Routes
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        users = mongo.db.users
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if users.find_one({"email": email}):
            flash("Email already registered.", "danger")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        user_id = users.insert_one({"username": username, "email": email, "password": hashed_password}).inserted_id
        user = User(user_id, username, email)  # Create User object for Flask-Login
        login_user(user)  # Log in the user
        flash("Registration successful! You are now logged in.", "success")
        return redirect(url_for('dashboard'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        users = mongo.db.users
        email = request.form['email']
        password = request.form['password']

        user = users.find_one({"email": email})
        if user and check_password_hash(user["password"], password):
            user_obj = User(str(user["_id"]), user["username"], user["email"])
            login_user(user_obj)  # Log in the user
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))

        flash("Invalid credentials. Try again.", "danger")

    return render_template('login.html')


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    passwords = mongo.db.passwords.find({"username": current_user.username})
    return render_template('dashboard.html', passwords=passwords)


@app.route('/save_password', methods=['POST'])
@login_required
def save_password():
    passwords = mongo.db.passwords
    website = request.form['website']
    url = request.form['url']
    password = request.form['password']

    # Encrypt the password before saving
    encrypted_password = cipher_suite.encrypt(password.encode()).decode()

    # Insert the encrypted password into the database
    passwords.insert_one({
        "username": current_user.username, 
        "website": website, 
        "url": url, 
        "password": encrypted_password
    })
    
    flash("Password saved successfully!", "success")
    return redirect(url_for('dashboard'))


@app.route('/get_password', methods=['POST'])
@login_required
def get_password():
    data = request.get_json()  # Parse the incoming JSON data
    website_name = data.get('website_name')

    # Fetch the password from the database using current_user.username
    password_record = mongo.db.passwords.find_one({
        "username": current_user.username, 
        "website": website_name
    })
    
    if not password_record:
        return jsonify({"error": "Password not found for the specified website"}), 404

    # Decrypt the password
    encrypted_password = password_record['password']
    try:
        decrypted_password = cipher_suite.decrypt(encrypted_password.encode()).decode()
    except Exception as e:
        return jsonify({"error": "Failed to decrypt password", "details": str(e)}), 500

    # Return the decrypted password in the response
    return jsonify({"website_name": website_name, "password": decrypted_password})


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
