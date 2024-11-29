from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from bson.objectid import ObjectId

import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# RSA Key Setup
def load_or_generate_keys():
    if not os.path.exists("private_key.pem") or not os.path.exists("public_key.pem"):
        # Generate a new private-public key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        # Save private key
        with open("private_key.pem", "wb") as priv_file:
            priv_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

        # Save public key
        with open("public_key.pem", "wb") as pub_file:
            pub_file.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

    # Load keys from files
    with open("private_key.pem", "rb") as priv_file:
        private_key = serialization.load_pem_private_key(
            priv_file.read(),
            password=None
        )

    with open("public_key.pem", "rb") as pub_file:
        public_key = serialization.load_pem_public_key(pub_file.read())

    return private_key, public_key


private_key, public_key = load_or_generate_keys()

# Encrypt Password
def encrypt_password(password):
    print(f"Encrypting password: {password}")
    encrypted = public_key.encrypt(
        password.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_base64 = base64.b64encode(encrypted).decode()
    print(f"Encrypted password (Base64): {encrypted_base64}")
    return encrypted_base64

# Decrypt Password
def decrypt_password(encrypted_password):
    print(f"Decrypting password: {encrypted_password}")
    try:
        decoded = base64.b64decode(encrypted_password)
        decrypted = private_key.decrypt(
            decoded,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Decrypted password: {decrypted.decode()}")
        return decrypted.decode()
    except Exception as e:
        print(f"Decryption failed: {e}")
        raise


# Flask App Setup
app = Flask(__name__)
app.secret_key = "your_secret_key"  # Use an environment variable for production

# MongoDB Config
app.config["MONGO_URI"] = "mongodb://localhost:27017/password_manager"
mongo = PyMongo(app)

# Flask-Login Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# User class for Flask-Login integration
class User(UserMixin):
    def __init__(self, id, username, email):
        self.id = str(id)  # MongoDB's ObjectId must be converted to a string
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
        user = User(user_id, username, email)
        login_user(user)
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
            login_user(user_obj)
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

    encrypted_password = encrypt_password(password)

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
    data = request.get_json()
    website_name = data.get('website_name')

    password_record = mongo.db.passwords.find_one({
        "username": current_user.username,
        "website": website_name
    })

    if not password_record:
        return jsonify({"error": "Password not found for the specified website"}), 404

    try:
        decrypted_password = decrypt_password(password_record['password'])
        return jsonify({"website_name": website_name, "password": decrypted_password})
    except Exception as e:
        return jsonify({"error": "Failed to decrypt password", "details": str(e)}), 500


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
