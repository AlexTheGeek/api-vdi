import schedule
import time
import mysql.connector
import back_openstack as openstack
import uuid
import datetime
import os

db_config = {
    'host': os.getenv('DB_HOST'),
    'database': os.getenv('DB_NAME'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
}

conn_openstack = openstack.conn

def synchronize_template_image():
    # Get image on the openstack
    images_openstack = openstack.get_image(conn_openstack)
    db = mysql.connector.connect(**db_config)
    cursor = db.cursor()
    cursor.execute("SELECT name FROM template")
    templates_db1 = cursor.fetchall()
    # Compare the two lists
    templates_db = []
    for template in templates_db1:
        templates_db.append(template[0])
    for image in images_openstack:
        if image not in templates_db:
            # Insert the image in the database
            cursor.execute("INSERT INTO template (id, name) VALUES (%s, %s)", (str(uuid.uuid4()), str(image)))
            db.commit()


    for template in templates_db:
        if template not in images_openstack:
            cursor.execute("DELETE FROM template WHERE name = %s", (template, ))
            db.commit()
            
    db.close()

def shutdown_vm():
    db = mysql.connector.connect(**db_config)
    cursor = db.cursor()
    cursor.execute("SELECT id, name FROM vm")
    vms_db = cursor.fetchall()
    for vm in vms_db:
        vm_state, status = openstack.get_status_server(conn_openstack, vm[1])
        if vm_state != 1:
            # Suppression de la VM sur l'openstack
            openstack.remove_instance(conn_openstack, vm[1])
            
            # Suppression de la VM dans la base de données
            cursor.execute("DELETE FROM vm WHERE id = %s", (vm[0], ))
            db.commit()
    db.close()


def check_active_vm():
    db = mysql.connector.connect(**db_config)
    cursor = db.cursor()
    cursor.execute("SELECT id, name, creationDate FROM vm")
    vms_db = cursor.fetchall()
    #Suppression si creationtime dépasse 2h
    for vm in vms_db:
        creationDate = vm[2]
        now = datetime.datetime.utcnow()
        if (now - creationDate).total_seconds() > 7200:
            # Suppression de la VM sur l'openstack
            openstack.remove_instance(conn_openstack, vm[1])
            
            # Suppression de la VM dans la base de données
            cursor.execute("DELETE FROM vm WHERE id = %s", (vm[0], ))
            db.commit()

# Schedule the job to run every 1 minute
schedule.every(1).minutes.do(synchronize_template_image)
schedule.every(2).minutes.do(shutdown_vm)
schedule.every(15).minutes.do(check_active_vm)

while True:
    schedule.run_pending()
    time.sleep(1)