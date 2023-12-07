##################
### Librairies ###
##################
from flask import Flask, request, jsonify, Response
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



################
### Vars APP ###
################
app = Flask(__name__)
CORS(app, supports_credentials=True)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:azerty@127.0.0.1/vdi2'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['TOKEN_SECRET_KEY'] = 'your_token_secret_key'
app.config['SESSION_COOKIE_DOMAIN'] = 'insa-cvl.com'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
#login_manager.login_view = 'login'

conn_openstack = openstack.conn


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
    name = db.Column(db.String(100), unique=True)
    template_id = db.Column(db.String(36))
    users_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    creationDate = db.Column(db.DateTime, default=datetime.datetime.utcnow)


# Template model
class Template(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=str(uuid.uuid4()), unique=True, nullable=False)
    name = db.Column(db.String(50))
    creationDate = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    users_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)


#################
### Functions ###
#################
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



##############
### Routes ###
##############
@app.route('/', methods=['GET'])
def welcome():
    return jsonify({'message': 'Hello and welcome to the VDI API!'})



###################
### User Routes ###
###################
@app.route('/register', methods=['POST'])
@login_required
def register():
    data = request.get_json()
    hashed_password = PasswordHasher().hash(data['password']) 
    new_user = User(id=str(uuid.uuid4()), email=data['email'], first_name=data['first_name'], last_name=data['last_name'],
                    password=hashed_password, role=data['role'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/logincas', methods=['GET', 'POST'])
def logincas():
    ticket_id = request.args.get('ticket')
    print(ticket_id)
    if ticket_id:
        validation_url = "https://cas.insa-cvl.fr/cas/serviceValidate?service=https%3A%2F%2Fapi.insa-cvl.com%2Flogincas&ticket="+ticket_id+"&attributes=cn,eduPersonPrincipalName,givenName,mail,sn,uid"
        try:
            response = requests.get(validation_url)
        except:
            return jsonify({'message': 'Ticket validation failed'}), 500
        print(response.text)
        return jsonify({'message': 'Login successful', "ticket_id" : ticket_id, "validation_url":validation_url}), 200
    return jsonify({'message': 'Ticket is missing'}), 404


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()

    if user and PasswordHasher().verify(user.password, data['password']):
        login_user(user)
        token = generate_token(user)

        # remove old token
        TokenUser.query.filter_by(users_id=user.id).delete()

        # Store token in tokens_user table
        new_token = TokenUser(users_id=user.id, token=token)

        db.session.add(new_token)
        db.session.commit()

        response = jsonify({'message': 'Login successful'})
        response.headers['Authorization'] = token
        print(response.headers)
        return response, 200
    else:
        return jsonify({'message': 'Invalid email or password'}), 401


@app.route('/logout')
@login_required
def logout():
    # remove token
    TokenUser.query.filter_by(users_id=current_user.id).delete()
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

@app.route('/check-auth')
@login_required
def check_auth():
    return jsonify({'message': 'Authentication check successful'})


##################
### VMs Routes ###
##################
@app.route('/vm', methods=['GET'])
@login_required
def get_vms():
    vms = VM.query.all()
    return jsonify([{"id": vm.id, "name":vm.name, "template_id": vm.template_id, "users_id": vm.users_id, "creationDate": vm.creationDate} for vm in vms]), 200

@app.route('/vm/create', methods=['POST'])
@login_required
def create_vm():
    data = request.get_json()
    new_vm = VM(id=str(uuid.uuid4()), name=data['template_id']+"---"+current_user.id, template_id=data['template_id'], users_id=current_user.id)
    template_name = Template.query.filter_by(id=data['template_id']).first().name
    try:
        openstack.create_instance(conn_openstack, data['template_id']+"---"+current_user.id, template_name)
    except:
        return jsonify({'message': 'VM creation failed'}), 500
    db.session.add(new_vm)
    db.session.commit()
    return jsonify({'message': 'VM created successfully'}), 201


@app.route('/vm/status/template/<template_id>', methods=['GET'])
@login_required
def vm_status_template(template_id):
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
def vm_url_ir(uuid):
    vm_name = VM.query.filter_by(id=uuid, users_id=current_user.id).first().name
    if vm_name:
        try:
            url_vnc = openstack.get_console_url(conn_openstack, vm_name)
        except:
            return jsonify({'message': 'ERROR URL'}), 500
        # resp = requests.get(url_vnc, verify=False)
        # excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        # headers = [(name, value) for (name, value) in  resp.raw.headers.items() if name.lower() not in excluded_headers]
        # response = Response(resp.iter_content(chunk_size=1024), resp.status_code, headers)
        # return response
        url = url_vnc.rsplit('0/vnc_auto.html', 1)[-1]
        print(url)
        return jsonify({"url": "https://vnc.insa-cvl.com/"+url}), 200
    else:
        return jsonify({'message': 'VM not found'}), 404

    

@app.route('/vm/url/template/<template_id>', methods=['GET'])
@login_required
def vm_url_template(template_id):
    vm_name = VM.query.filter_by(template_id=template_id, users_id=current_user.id).first().name
    if vm_name:
        try:
            url_vnc = openstack.get_console_url(conn_openstack, vm_name)
        except:
            return jsonify({'message': 'ERROR URL'}), 500
        # resp = requests.get(url_vnc, verify=False, stream=True)
        # excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        # headers = [(name, value) for (name, value) in  resp.raw.headers.items() if name.lower() not in excluded_headers]
        # response = Response(resp.iter_content(chunk_size=1024), resp.status_code, headers)
        # return response
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
    new_template = Template(id=str(uuid.uuid4()), name=data['name'], users_id=current_user.id)
    db.session.add(new_template)
    db.session.commit()
    return jsonify({'message': 'Template created successfully'}), 201

@app.route('/template/delete', methods=['DELETE'])
@login_required
def delete_template():
    data = request.get_json()
    template_id = data.get('template_id')
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
    with app.app_context():
        db.create_all()
    app.run(debug=True, host="0.0.0.0", port=5001)