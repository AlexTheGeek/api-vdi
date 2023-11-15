from flask import Flask, jsonify, request
import mariadb
import uuid
import secrets
import back_openstack as openstack
import db

conn_openstack = openstack.conn


app = Flask(__name__)

# configuration used to connect to MariaDB
config = {
    'host': '127.0.0.1',
    'port': 3306,
    'user': 'root',
    'password': 'azerty',
    'database': 'vdi'
}



# General API
@app.route('/', methods=['GET'])
def root_api():
    message = {
        "message": "Hello ! This is the API for the VDI project."
    }
    return jsonify(message)


@app.route('/version', methods=['GET'])
def version():
    message = {
        "version": "0.0.1"
    }
    return jsonify(message)



# Users
@app.route('/login', methods=['POST'])
def login():
    pass


@app.route('/logout', methods=['POST'])
def logout():
    pass


@app.route('/register', methods=['POST'])
def register():
    # JSON format
    format = {
        "first_name" : "Alexis",
        "last_name" : "Brunet",
        "email" : "alexis.brunet@insa-cvl.fr",
        "password" : "azerty",
    }
    
    # Check if a Content-type Application/json is present
    if request.headers.get('Content-Type') != 'application/json':
        return jsonify(format), 400

    
    # Getting the json from the post request
    first_name = request.json['first_name']
    last_name = request.json['last_name']
    email = request.json['email']
    password = request.json['password']
    
    # Check if first_name, last_name, email and password are empty
    if first_name == "" or last_name == "" or email == "" or password == "":
        return jsonify(format), 400


    conn = mariadb.connect(**config)
    # Check if user already exists
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email=?", (email,))
        user = cur.fetchone()
        if user is not None:
            return jsonify({"message": "User already exists"}), 400
    except mariadb.Error as e:
        print(f"Error connecting to MariaDB Platform: {e}")
        return jsonify({"message": "Error connecting to MariaDB Platform"}), 500

        
    # Generate a uuid
    uuid_user = uuid.uuid4()
    
    
    # Generate a token
    token = secrets.token_hex(16)
    
    # Add the user to the database

    try:
        cur = conn.cursor()
        # Add the user to the users table
        cur.execute("INSERT INTO users (uuid, first_name, last_name, email, password) VALUES (?, ?, ?, ?, ?)", (str(uuid_user),first_name, last_name, email, password))
        # Add the token to the tokens_user table
        cur.execute("INSERT INTO tokens_user (uuid_user, token) VALUES (?, ?)", (str(uuid_user), str(token)))
        conn.commit()
    except mariadb.Error as e:
        print(f"Error connecting to MariaDB Platform: {e}")
        return jsonify({"message": "Error connecting to MariaDB Platform"}), 500

    conn.close()

    return jsonify({"message": "User created"}), 201


# Bearer token
@app.route('/user', methods=['GET'])
def user():
    # JSON format
    format = {
        "email" : "alexis.brunet@insa-cvl.fr",
    }
    
    # Check if a Content-type Application/json is present
    if request.headers.get('Content-Type') != 'application/json':
        return jsonify(format), 400

    
    # Getting the json from the post request
    email = request.json['email']
    
    if email == "":
        return jsonify(format), 400
    
    # Get Infos about the user in the database
    conn = mariadb.connect(**config)
    try:
        cur = conn.cursor()
        cur.execute(f"SELECT * FROM users WHERE email='{email}'")
        user = cur.fetchone()
        if user is None:
            return jsonify({"message": "User not found"}), 404
    except mariadb.Error as e:
        print(f"Error connecting to MariaDB Platform: {e}")
        return jsonify({"message": "Error connecting to MariaDB Platform"}), 500
    
    conn.close()
    
    # Show the user infos
    return jsonify({"message": "User found", "user": user}), 200
    


# Bearer token
@app.route('/change_password', methods=['POST'])
def change_password():
    format = {
        "token" : "token",
        "email" : "email",
        "old_password" : "old_password",
        "new_password" : "new_password"
    }
    
    # Check if a Content-type Application/json is present
    if request.headers.get('Content-Type') != 'application/json':
        return jsonify(format), 400

    
    # Getting the json from the post request
    token = request.json['token']
    email = request.json['email']
    old_password = request.json['old_password']
    new_password = request.json['new_password']
    
    
    if token == "" or email == "" or old_password == "" or new_password == "":
        return jsonify(format), 400
    
    
    # Check if the token is valid for the uuid_user
    conn = mariadb.connect(**config)
    try:
        # Get the uuid_user from the email
        cur = conn.cursor()
        cur.execute("SELECT uuid FROM users WHERE email=?", (email,))
        uuid_user = cur.fetchone()
        if uuid_user is None:
            return jsonify({"message": "User not found"}), 404
        
        # Check if the token is valid
        cur = conn.cursor()
        cur.execute("SELECT * FROM tokens_user WHERE uuid_user=? AND token=?", (uuid_user, token))
        token = cur.fetchone()
        if token is None:
            return jsonify({"message": "Token not valid"}), 400
        
        # Check if the old_password is correct
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE uuid=? AND password=?", (uuid_user, old_password))
        user = cur.fetchone()
        if user is None:
            return jsonify({"message": "Old password not valid"}), 400

        # Update the password
        cur = conn.cursor()
        cur.execute("UPDATE users SET password=? WHERE uuid=?", (new_password, uuid_user))
        conn.commit()

    except mariadb.Error as e:
        print(f"Error connecting to MariaDB Platform: {e}")
        return jsonify({"message": "Error connecting to MariaDB Platform"}), 500
    
    conn.close()
    
    return jsonify({"message": "Password changed"}), 200


## VMs
@app.route('/vm/create', methods=['POST'])
def create_vm():
    format = {
        "template_name" : "ubuntu",
        "user_id" : "uuid",
    }
    
    # Check if a Content-type Application/json is present
    if request.headers.get('Content-Type') != 'application/json':
        return jsonify(format), 400

    
    # Getting the json from the post request
    template = request.json['template_name']
    user_id = request.json['user_id']
    
    if template == "" or user_id == "":
        return jsonify(format), 400
    
   
    # Add the new vm to the database
    # Generate a uuid
    uuid_vm = uuid.uuid4()
    
    try:
        openstack.create_instance(conn_openstack, uuid_vm, template)
    except:
        return jsonify({"message": "Error during the VM creation"}), 500
    
    conn = mariadb.connect(**config)
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO vms (uuid, template_name, user_uuid) VALUES (?, ?, ?)", (str(uuid_vm), template, str(user_id)))
        conn.commit()
    except mariadb.Error as e:
        print(f"Error connecting to MariaDB Platform: {e}")
        return jsonify({"message": "Error connecting to MariaDB Platform"}), 500
    
    conn.close()
    
    return jsonify({"message": "VM created"}), 201

        

# Bearer token
@app.route('/vm/infos', methods=['POST'])
def status_vm():
    format = {
        "vm_name" : "je suis le nom de ta machine",
        "user_id" : "uuid",
    }
    
    # Check if a Content-type Application/json is present
    if request.headers.get('Content-Type') != 'application/json':
        return jsonify(format), 400

    
    # Getting the json from the post request
    vm_name = request.json['vm_name']
    user_id = request.json['user_id']
    
    if vm_name == "" or user_id == "":
        return jsonify(format), 400
    
    # Check if a vm is already running for the user with the same vm_name
    conn = mariadb.connect(**config)
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM vms WHERE user_uuid=? AND vm_name=?", (str(user_id), vm_name))
        vm = cur.fetchone()
        if vm is not None:
            return jsonify({"message": "VM already exists"}), 400           
        
    except mariadb.Error as e:
        print(f"Error connecting to MariaDB Platform: {e}")
        return jsonify({"message": "Error connecting to MariaDB Platform"}), 500
    
    

@app.route('/vm/delete', methods=['POST'])
def delete_vm():
    format = {
        "template_name" : "ubuntu",
        "user_id" : "uuid",
    }
    
    # Check if a Content-type Application/json is present
    if request.headers.get('Content-Type') != 'application/json':
        return jsonify(format), 400

    
    # Getting the json from the post request
    template = request.json['template']
    user_id = request.json['user_id']
    
    if template == "" or user_id == "":
        return jsonify(format), 400
    
   
    # Add the new vm to the database
    # Generate a uuid
    uuid_vm = uuid.uuid4()
    
    try:
        openstack.remove_instance(conn_openstack, uuid_vm)
    except:
        return jsonify({"message": "Error during the VM creation"}), 500
    
    conn = mariadb.connect(**config)
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO vms (uuid, template_name, user_uuid) VALUES (?, ?, ?)", (str(uuid_vm), template, str(user_id)))
        conn.commit()
    except mariadb.Error as e:
        print(f"Error connecting to MariaDB Platform: {e}")
        return jsonify({"message": "Error connecting to MariaDB Platform"}), 500
    
    conn.close()
    
    return jsonify({"message": "VM created"}), 201





if __name__ == '__main__':
    db.drop_database("vdi")
    db.create_database("vdi")
    db.init_database()
    app.secret_key = 'fhjkdhgjdkfghdfkj'
    app.run(debug=True, host="0.0.0.0")