##################
### Librairies ###
##################
from flask import Flask, request, jsonify, Response, redirect, render_template, abort, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
import uuid
import datetime
import mysql.connector
from argon2 import PasswordHasher
import back_openstack as openstack
from flask_cors import CORS
import requests
import xml.etree.ElementTree as ET
import random
import string
from functools import wraps
from flask_migrate import Migrate
import logging
import os

################
### Vars APP ###
################
app = Flask(__name__)
CORS(app, supports_credentials=True)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:azerty@127.0.0.1/vdi3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['TOKEN_SECRET_KEY'] = 'your_token_secret_key'
app.config['SESSION_COOKIE_DOMAIN'] = 'insa-cvl.com'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
#login_manager.login_view = 'login'

conn_openstack = openstack.conn


##################
### Log config ###
##################
# Create a custom logger
logger = logging.getLogger("API-VDI")
logging.basicConfig(level = logging.INFO)

# Create handlers
if not os.path.exists('/var/log/VDI/API'):
    os.makedirs('/var/log/VDI/API')
    os.system("chown -R alex:alex /var/log/VDI")
f_handler = logging.FileHandler('/var/log/VDI/API/api-flask.log')
f_handler.setLevel(logging.INFO)

# Create formatters and add it to handlers
f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
f_handler.setFormatter(f_format)

# Add handlers to the logger
logger.addHandler(f_handler)
# logger.debug('This is a debug message')
# logger.info('This is an info message')
# logger.warning('This is a warning message')
# logger.error('This is an error message')
# logger.critical('This is a critical message')



##########
### DB ###
##########

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.String(36), primary_key=True, default=str(uuid.uuid4()), unique=True, nullable=False)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20))
    cas = db.Column(db.Boolean, default=True)
    parent = db.Column(db.String(36))
    tokens = db.relationship('TokenUser', backref='user', lazy=True) # A supprimer
    vms = db.relationship('VM', backref='user', lazy=True)
    templates = db.relationship('Template', backref='user', lazy=True)


# TokenUser model (A supprimer)
class TokenUser(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=str(uuid.uuid4()), unique=True, nullable=False)
    users_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(200))
    creationDate = db.Column(db.DateTime, default=datetime.datetime.utcnow)


# VM model
class VM(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=str(uuid.uuid4()), unique=True, nullable=False)
    name = db.Column(db.String(100), unique=True)
    template_id = db.Column(db.String(36))
    users_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    # vncurl = db.Column(db.String(200))
    creationDate = db.Column(db.DateTime, default=datetime.datetime.utcnow)


# Template model
class Template(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=str(uuid.uuid4()), unique=True, nullable=False)
    name = db.Column(db.String(50), unique=True, nullable=False)
    creationDate = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    users_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=True)


#################
### Functions ###
#################
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(str(user_id))


# Token Serializer
# def generate_token(user):
#     serializer = URLSafeTimedSerializer(app.config['TOKEN_SECRET_KEY'])
#     return serializer.dumps({'user_id': user.id})


# Middleware for token-based authentication

#@app.before_request
# def check_token():
#     # if request.endpoint not in ['login', 'register', 'check_auth'] and not current_user.is_authenticated:
#     token = request.headers.get('Authorization')
#     if not token:
#         return jsonify({'message': 'Token is missing'}), 401

#     user = User.query.join(TokenUser).filter(TokenUser.token == token).first()
#     if user:
#         login_user(user)
#     else:
#         return jsonify({'message': 'Invalid token'}), 401

def extract_user_info(xml_response):
    user_info = {}
    root = ET.fromstring(xml_response)

    # Find the <cas:authenticationSuccess> element
    auth_success_element = root.find('.//cas:authenticationSuccess', namespaces={'cas': 'http://www.yale.edu/tp/cas'})

    if auth_success_element is not None:
        # Extract the <cas:user> element (user ID)
        user_info['user_id'] = auth_success_element.find('.//cas:user', namespaces={'cas': 'http://www.yale.edu/tp/cas'}).text

        # Extract attributes if present
        attributes_element = auth_success_element.find('.//cas:attributes', namespaces={'cas': 'http://www.yale.edu/tp/cas'})
        if attributes_element is not None:
            for attribute in attributes_element:
                # Assume that each attribute is a key-value pair
                user_info[attribute.tag[28:]] = attribute.text

    return user_info

def get_random_string(length):
    # choose from all lowercase letter
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

def check_student(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if hasattr(current_user, 'role') and 'user' in current_user.role:
            return func(*args, **kwargs)
        else:
            abort(403)
    return wrapper

def check_admin(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if hasattr(current_user, 'role') and 'admin' in current_user.role:
            return func(*args, **kwargs)
        else:
            abort(403)
    return wrapper

def check_prof(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if hasattr(current_user, 'role') and 'prof' in current_user.role:
            return func(*args, **kwargs)
        else:
            abort(403)
    return wrapper

def check_prof_admin(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if hasattr(current_user, 'role') and ('prof' in current_user.role or 'admin' in current_user.role):
            return func(*args, **kwargs)
        else:
            abort(403)
    return wrapper


##############
### Routes ###
##############
@app.route('/', methods=['GET'])
def welcome():
    logger.info("Welcome access")
    return jsonify({'message': 'Hello and welcome to the VDI API!'})



###################
### User Routes ###
###################
@app.route('/register', methods=['POST'])
@login_required
def register():
    data = request.get_json()
    if not data or not data['email'] or not data['password'] or not data['first_name'] or not data['last_name'] or not data['role']:
        logger.warning("User creation failed: "+data['email'])
        return jsonify({'message': 'Please provide all the required informations (email, password, first_name, last_name)'}), 400
    hashed_password = PasswordHasher().hash(data['password']) 
    new_user = User(id=str(uuid.uuid4()), email=data['email'], first_name=data['first_name'], last_name=data['last_name'],
                    password=hashed_password, cas=False, role=data['role'])
    db.session.add(new_user)
    db.session.commit()
    logger.info("User created: "+data['email'])
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/createuser', methods=['POST'])
@login_required
@check_prof_admin
def create_user():
    data = request.get_json()
    if not data or not data['email'] or not data['first_name'] or not data['last_name']:
        logger.warning("User creation failed: "+data['email']+ " by "+current_user.email)
        return jsonify({'message': 'Please provide all the required informations (email, first_name, last_name)'}), 400
    random_password = get_random_string(15)
    print(random_password)
    hashed_password = PasswordHasher().hash(random_password) 
    new_user = User(id=str(uuid.uuid4()), email=data['email'], first_name=data['first_name'], last_name=data['last_name'],
                    password=hashed_password, role="user", cas=False, parent=current_user.id)
    db.session.add(new_user)
    db.session.commit()
    logger.info("User created: "+data['email']+ " by "+current_user.email)
    return jsonify({'message': 'User created successfully', 'password': random_password}), 201

@app.route('/updatepassword', methods=['POST'])
@login_required
def update_password():
    data = request.get_json()
    if data['user_id']:
        user_id = data['user_id']
    else:
        user_id = current_user.id
    if not data or not data['old_password'] or not data['new_password'] or not data['new_password2']:
        return jsonify({'message': 'Please provide a new password'}), 400
    user = User.query.filter_by(id=user_id).first()
    if PasswordHasher().verify(user.password, data['old_password']):
        if data['new_password'] == data['new_password2']:
            hashed_password = PasswordHasher().hash(data['new_password']) 
            user.password = hashed_password
            db.session.commit()
            logger.info("Password updated: "+user.email+ " by "+current_user.email)
            return jsonify({'message': 'Password updated successfully'}), 200
        else:
            logger.warning("Password update failed: "+user.email+ " by "+current_user.email)
            return jsonify({'message': 'New passwords do not match'}), 400

@app.route('/updaterole', methods=['POST'])
@login_required
@check_admin
def update_role():
    data = request.get_json()
    if not data or not data['role'] or not data['user_id']:
        logger.warning("Role update failed: "+data['user_id']+ " by "+current_user.email)
        return jsonify({'message': 'Please provide a new role and the user_id'}), 400
    user = User.query.filter_by(id=data['user_id']).first()
    user.role = data['role']
    db.session.commit()
    logger.info("Role updated: "+data['user_id']+ " by "+current_user.email)
    return jsonify({'message': 'Role updated successfully'}), 200

# @app.route('/deleteuser', methods=['DELETE'])
# @login_required
# @check_prof_admin
# ### TODO


@app.route('/logincas', methods=['GET', 'POST'])
def logincas():
    ticket_id = request.args.get('ticket')
    print(ticket_id)
    if ticket_id:
        validation_url = "https://cas.insa-cvl.fr/cas/p3/serviceValidate?service=https%3A%2F%2Fapi.insa-cvl.com%2Flogincas&ticket="+ticket_id
        # validation_url = "https://cas.insa-cvl.fr/cas/serviceValidate?service=https%3A%2F%2Fapi.insa-cvl.com%2Flogincas&ticket="+ticket_id+"&attributes=cn,eduPersonPrincipalName,givenName,mail,sn,uid"
        try:
            response = requests.get(validation_url)
        except:
            return jsonify({'message': 'Ticket validation failed'}), 500
        print(response.text)
        user_attributes = extract_user_info(response.text)
        print(user_attributes['user_id'])
        user = User()
        user.id = user_attributes['user_id']
        user.email = user_attributes['user_id']+"@insa-cvl.fr" #user_attributes['mail']
        user.first_name = user_attributes['user_id'] #user_attributes['givenName']
        user.last_name = user_attributes['user_id'] #user_attributes['sn']
        user.password = PasswordHasher().hash(user_attributes['user_id'])
        user.role = "user"

        user_db = User.query.filter_by(id=user.id).first()
        if user_db:
            user = user_db
        else:
            db.session.add(user)
            db.session.commit()
                
        login_user(user)
        # token = generate_token(user)

        # # remove old token
        # TokenUser.query.filter_by(users_id=user.id).delete()

        # # Store token in tokens_user table
        # new_token = TokenUser(users_id=user.id, token=token)

        # db.session.add(new_token)
        # db.session.commit()

        # custom_headers = {'Authorization': token}
        logger.info("Login successful: "+user_attributes['user_id'])
        return redirect("https://vdi.insa-cvl.com/dashboard")
        # return render_template('login_redirect', custom_headers=custom_headers)

        # response = jsonify({'message': 'Login successful'})
        # response.headers['Authorization'] = token
        # print(response.headers)
        # return response, 200
        # return redirect("https://vdi.insa-cvl.com/student")       
        # return jsonify({'message': 'Login successful', "ticket_id" : ticket_id, "validation_url":validation_url, "user_id": user_attributes['user_id']}), 200
    logger.warning("Login failed: "+user_attributes['user_id'])
    return jsonify({'message': 'Ticket is missing'}), 404


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or not data['email'] or not data['password']:
        logger.warning("Login failed: "+data['email'])
        return jsonify({'message': 'Please provide email and password'}), 400
    
    user = User.query.filter_by(email=data['email']).first()
    
    if user.email.find("@insa-cvl.fr") != -1 or user.cas == True:
        logger.warning("Login failed: "+data['email'] + " without CAS")
        return jsonify({'message': 'Please use CAS login'}), 403
    
    if user and PasswordHasher().verify(user.password, data['password']):
        login_user(user)
        # token = generate_token(user)

        # # remove old token
        # TokenUser.query.filter_by(users_id=user.id).delete()
        # db.session.commit()
        
        # # Store token in tokens_user table
        # new_token = TokenUser(users_id=user.id, token=token)

        # db.session.add(new_token)
        # db.session.commit()

        # response = jsonify({'message': 'Login successful'})
        # response.headers['Authorization'] = token
        # print(response.headers)
        logger.info("Login successful: "+data['email'])
        return jsonify({'message': 'Login successful'}), 200
    else:
        logger.warning("Login failed: "+data['email'])
        return jsonify({'message': 'Invalid email or password'}), 401


@app.route('/logout')
@login_required
def logout():
    # remove token
    # TokenUser.query.filter_by(users_id=current_user.id).delete()
    # db.session.commit()
    user = User.query.filter_by(id=current_user.id).first()
    logout_user()
    if user.cas:
        logger.info("User logout: "+user.email+" with CAS")
        return jsonify({'message': 'Logout successful', 'cas': True}), 200
        # return redirect("https://cas.insa-cvl.fr/cas/logout?service=https%3A%2F%2Fapi.insa-cvl.com")
    logger.info("User logout: "+user.email)
    return jsonify({'message': 'Logout successful', 'cas': False}), 200


@app.route('/profile')
@login_required
def profile():
    logger.info("Profile access: "+current_user.email+", role: "+current_user.role+", id: "+current_user.id)
    return jsonify({
        'id': current_user.id,
        'first_name': current_user.first_name,
        'last_name': current_user.last_name,
        'email': current_user.email,
        'role': current_user.role,
        'parent': current_user.parent,
        'cas': current_user.cas
    })

@app.route('/check-auth')
@login_required
def check_auth():
    logger.info("Authentication check: "+current_user.email+", role: "+current_user.role+", id: "+current_user.id)
    return jsonify({'message': 'Authentication check successful'})


@app.route('/users', methods=['GET'])
@login_required
@check_admin
def get_users():
    users = User.query.all()
    logger.info("Users list access: "+current_user.email+", role: "+current_user.role+", id: "+current_user.id)
    return jsonify([{"id":user.id, "first_name":user.first_name, "last_name":user.last_name, "email":user.email, "role":user.role} for user in users]), 200

@app.route('/roles', methods=['GET'])
@login_required
@check_admin
def get_roles():
    roles = ["user", "prof", "admin"]
    logger.info("Roles list access: "+current_user.email+", role: "+current_user.role+", id: "+current_user.id)
    return jsonify(roles), 200

@app.route('/myusers', methods=['GET'])
@login_required
@check_prof
def get_myusers():
    users = User.query.filter(User.query.filter_by(parent=current_user.id)).all()
    logger.info("My Users list access: "+current_user.email+", role: "+current_user.role+", id: "+current_user.id)
    return jsonify([{"id":user.id, "first_name":user.first_name, "last_name":user.last_name, "email":user.email, "role":user.role, "cas": user.cas, "parent": user.parent} for user in users]), 200

##################
### VMs Routes ###
##################
@app.route('/vm', methods=['GET'])
@login_required
@check_admin
def get_vms():
    vms = VM.query.all()
    return jsonify([{"id": vm.id, "name":vm.name, "template_id": vm.template_id, "users_id": vm.users_id, "creationDate": vm.creationDate} for vm in vms]), 200

@app.route('/myvmsusers', methods=['GET'])
@login_required
@check_prof
def get_myvmsusers():
    # à changer
    vm = VM.query.filter(VM.users_id.like("%"+current_user.id)).all()
    return jsonify([{"id": vm.id, "name":vm.name, "template_id": vm.template_id, "users_id": vm.users_id, "creationDate": vm.creationDate} for vm in vm]), 200

@app.route('/vm/create', methods=['POST'])
@login_required
def create_vm():
    data = request.get_json()
    if not data or not data['template_id']:
        return jsonify({'message': 'Please provide a template ID'}), 400
    
    if VM.query.filter_by(template_id=data['template_id'], users_id=current_user.id).all():
        return jsonify({'message': 'VM already exists'}), 409
    
    new_vm = VM(id=str(uuid.uuid4()), name=data['template_id']+"---"+current_user.id, template_id=data['template_id'], users_id=current_user.id)
    template_name = Template.query.filter_by(id=data['template_id']).first().name
    try:
        openstack.create_instance(conn_openstack, data['template_id']+"---"+current_user.id, template_name)
    except:
        return jsonify({'message': 'VM creation failed'}), 500
    # try:
    #     url_vnc = openstack.get_console_url(conn_openstack, data['template_id']+"---"+current_user.id)
    # except:
    #     return jsonify({'message': 'ERROR URL'}), 500
    # new_vm.vncurl = url_vnc.rsplit('0/vnc_auto.html?path=', 1)[-1]
    db.session.add(new_vm)
    db.session.commit()
    return jsonify({'message': 'VM created successfully'}), 201


@app.route('/vm/status/template/<template_id>', methods=['GET'])
@login_required
def vm_status_template(template_id):
    if not template_id:
        return jsonify({'message': 'Please provide a template ID'}), 400
    try:
        vm = VM.query.filter_by(template_id=template_id, users_id=current_user.id).first()
    except:
        return jsonify({'message': 'DB ERROR'}), 500
    if vm:
        try:
            print(vm.name)
            vm_state, status = openstack.get_status_server(conn_openstack, vm.name)
            print(vm_state)
        except:
            return jsonify({'message': 'VM STATUS FAILLED'}), 500
        return jsonify({"status": status, "vm_state": vm_state}), 200
    else:
        return jsonify({'status': 'stopped'}), 200



@app.route('/vm/status/id/<uuid>', methods=['GET'])
@login_required
def vm_status_id(uuid):
    if not uuid:
        return jsonify({'message': 'Please provide a VM ID'}), 400
    try:
        vm = VM.query.filter_by(id=uuid, users_id=current_user.id).first()
        if vm:
            vm_state, status = openstack.get_status_server(conn_openstack, vm.name)
            return jsonify({"status": status, "vm_state": vm_state}), 200
        else:
            return jsonify({'status': 'stopped'}), 200
    except:
        return jsonify({'message': 'VM status failed'}), 500
    
@app.route('/vm/url/id/<uuid>', methods=['GET'])
@login_required
def vm_url_id(uuid):
    if not uuid:
        return jsonify({'message': 'Please provide a VM ID'}), 400
    vm_name = VM.query.filter_by(id=uuid, users_id=current_user.id).first().name
    if vm_name:
        try:
            url_vnc = openstack.get_console_url(conn_openstack, vm_name)
        except:
            return jsonify({'message': 'ERROR URL'}), 500
        url = url_vnc.rsplit('0/vnc_auto.html', 1)[-1]
        print(url)
        return jsonify({"url": "https://vnc.insa-cvl.com/"+url}), 200
    else:
        return jsonify({'message': 'VM not found'}), 404

    

@app.route('/vm/url/template/<template_id>', methods=['GET'])
@login_required
def vm_url_template(template_id):
    if not template_id:
        return jsonify({'message': 'Please provide a template ID'}), 400
    vm_name = VM.query.filter_by(template_id=template_id, users_id=current_user.id).first().name
    if vm_name:
        try:
            url_vnc = openstack.get_console_url(conn_openstack, vm_name)
        except:
            return jsonify({'message': 'ERROR URL'}), 500
        print(url_vnc)
        url = url_vnc.rsplit('0/vnc_auto.html', 1)[-1]
        print(url)
        return jsonify({"url": "https://vnc.insa-cvl.com/"+url}), 200
    else:
        return jsonify({'message': 'Template not found'}), 404


@app.route('/vm/delete', methods=['DELETE'])
@login_required
def delete_vm():
    data = request.get_json()
    template_id = data.get('template_id')
    if not template_id:
        return jsonify({'message': 'Please provide a template ID'}), 400
    if template_id:
        vm = VM.query.filter_by(template_id=template_id, users_id=current_user.id).first()
        if vm:
            try:
                server = conn_openstack.compute.find_server(vm.name)
                conn_openstack.compute.delete_server(server)
            except:
                return jsonify({'message': 'VM deletion failed'}), 500
            db.session.delete(vm)
            db.session.commit()
            return jsonify({'message': 'VM deleted successfully'}), 200
        else:
            return jsonify({'message': 'VM not found or unauthorized'}), 404
    else:
        return jsonify({'message': 'VM ID is required'}), 400


#######################
### Template Routes ###
#######################
@app.route('/template', methods=['GET'])
@login_required
def get_templates():
    templates = Template.query.all()
    return jsonify([{"id":template.id, "name":template.name, "users_id":template.users_id, "creationDate":template.creationDate} for template in templates]), 200

@app.route('/template/create', methods=['POST'])
@login_required
def create_template():
    data = request.get_json()
    if not data or not data['name']:
        return jsonify({'message': 'Please provide a name'}), 400
    new_template = Template(id=str(uuid.uuid4()), name=data['name'], users_id=current_user.id)
    db.session.add(new_template)
    db.session.commit()
    return jsonify({'message': 'Template created successfully'}), 201

@app.route('/template/delete', methods=['DELETE'])
@login_required
def delete_template():
    data = request.get_json()
    template_id = data.get('template_id')
    if not template_id:
        return jsonify({'message': 'Please provide a template ID'}), 400
    if template_id:
        template = Template.query.filter_by(id=template_id, users_id=current_user.id).first()
        if template:
            db.session.delete(template)
            db.session.commit()
            return jsonify({'message': 'Template deleted successfully'}), 200
        else:
            return jsonify({'message': 'Template not found or unauthorized'}), 404
    else:
        return jsonify({'message': 'Template ID is required'}), 400


@app.route('/template/info/<uuid>', methods=['GET'])
@login_required
def get_template_info(uuid):
    if not uuid:
        return jsonify({'message': 'Please provide a template ID'}), 400
    if uuid:
        template = Template.query.filter_by(id=uuid).first()
        if template:
            # Ajouter la récupération des infos du tempalte depuis OpenStack
            return jsonify({'message': 'Template found successfully'}), 200
        else:
            return jsonify({'message': 'Template not found'}), 404
    else:
        return jsonify({'message': 'Template ID is required'}), 400



if __name__ == '__main__':
    logger.info('Starting API')
    with app.app_context():
        logger.info('Creating DB')
        db.create_all()
        db.session.commit()
        # Create default admin user
        if not User.query.filter_by(email="openstack@insa-cvl.fr").first():
            logger.info('Creating default admin user')
            random_password = get_random_string(15)
            hashed_password = PasswordHasher().hash(random_password) 
            new_user = User(id="1", email="openstack@insa-cvl.fr", first_name="openstack", last_name="openstack",
                            password=hashed_password, role="admin", cas=True)
            db.session.add(new_user)
            db.session.commit()
            logger.info("Default admin user created with password: "+random_password)
            # print("Default admin user created with password: "+random_password)
    logger.info('API started')
    app.run(debug=True, host="0.0.0.0", port=5001)