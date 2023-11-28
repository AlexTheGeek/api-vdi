from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
import uuid
import datetime
import mysql.connector

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:azerty@127.0.0.1/vdi2'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['TOKEN_SECRET_KEY'] = 'your_token_secret_key'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# User model
class User(UserMixin, db.Model):
    id = db.Column(db.String(36), primary_key=True, default=str(uuid.uuid4()), unique=True, nullable=False)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20))
    tokens = db.relationship('TokenUser', backref='user', lazy=True)
    vms = db.relationship('VM', backref='user', lazy=True)
    templates = db.relationship('Template', backref='user', lazy=True)


# TokenUser model
class TokenUser(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=str(uuid.uuid4()), unique=True, nullable=False)
    users_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(200))
    creationDate = db.Column(db.DateTime, default=datetime.datetime.utcnow)


# VM model
class VM(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=str(uuid.uuid4()), unique=True, nullable=False)
    template_id = db.Column(db.String(36))
    users_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    creationDate = db.Column(db.DateTime, default=datetime.datetime.utcnow)


# Template model
class Template(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=str(uuid.uuid4()), unique=True, nullable=False)
    name = db.Column(db.String(50))
    creationDate = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    users_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(str(user_id))


# Token Serializer
def generate_token(user):
    serializer = URLSafeTimedSerializer(app.config['TOKEN_SECRET_KEY'])
    return serializer.dumps({'user_id': user.id})


# Middleware for token-based authentication
#@app.before_request
def check_token():
    # if request.endpoint not in ['login', 'register', 'check_auth'] and not current_user.is_authenticated:
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing'}), 401

    user = User.query.join(TokenUser).filter(TokenUser.token == token).first()
    if user:
        login_user(user)
    else:
        return jsonify({'message': 'Invalid token'}), 401


# Routes
@app.route('/', methods=['GET'])
def welcome():
    return jsonify({'message': 'Hello and welcome to the VDI API!'})

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(email=data['email'], first_name=data['first_name'], last_name=data['last_name'],
                    password=hashed_password, role=data['role'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()

    if user and check_password_hash(user.password, data['password']):
        login_user(user)
        token = generate_token(user)

        # Store token in tokens_user table
        new_token = TokenUser(users_id=user.id, token=token)
        db.session.add(new_token)
        db.session.commit()

        response = jsonify({'message': 'Login successful'})
        response.headers['Authorization'] = token
        return response, 200
    else:
        return jsonify({'message': 'Invalid email or password'}), 401


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logout successful'}), 200


@app.route('/profile')
@login_required
def profile():
    return jsonify({
        'id': current_user.id,
        'first_name': current_user.first_name,
        'last_name': current_user.last_name,
        'email': current_user.email,
        'role': current_user.role
    })


@app.route('/vm/create', methods=['POST'])
@login_required
def create_vm():
    data = request.get_json()
    new_vm = VM(template_id=data['template_id'], users_id=current_user.id)
    db.session.add(new_vm)
    db.session.commit()
    return jsonify({'message': 'VM created successfully'}), 201


@app.route('/vm/status', methods=['GET'])
@login_required
def vm_status():
    # You can implement the logic to retrieve and return the status of a VM based on the user's ID
    return jsonify({'message': 'VM status endpoint'})


@app.route('/vm/delete', methods=['DELETE'])
@login_required
def delete_vm():
    data = request.get_json()
    vm_id = data.get('vm_id')
    if vm_id:
        vm = VM.query.filter_by(id=vm_id, users_id=current_user.id).first()
        if vm:
            db.session.delete(vm)
            db.session.commit()
            return jsonify({'message': 'VM deleted successfully'}), 200
        else:
            return jsonify({'message': 'VM not found or unauthorized'}), 404
    else:
        return jsonify({'message': 'VM ID is required'}), 400


@app.route('/check-auth')
@login_required
def check_auth():
    return jsonify({'message': 'Authentication check successful'})


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host="0.0.0.0")