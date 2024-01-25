import schedule
import time
import mysql.connector
import back_openstack as openstack
import uuid
import datetime

db_config = {
    'host': '127.0.0.1',
    'database': 'vdi3',
    'user': 'root',
    'password': 'azerty',
}

conn_openstack = openstack.conn

def job():
    print("Job is running...")

def synchronize_template_image():
    # Get image on the openstack
    images_openstack = openstack.get_image(conn_openstack)
    # Get template from the database
    print(images_openstack)
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
            cursor.execute("INSERT INTO template (id, name, users_id) VALUES (%s, %s, %s)", (str(uuid.uuid4()), str(image), "1"))
            # cursor.execute("INSERT INTO template (id, name) VALUES (%s, %s)", (str(uuid.uuid4()), str(image)))
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
            # Suppression de la VMs sur l'openstack
            server = conn_openstack.compute.find_server(vm[1])
            conn_openstack.compute.delete_server(server)
            
            # Suppression de la VMs dans la base de données
            cursor.execute("DELETE FROM vm WHERE id = %s", (vm[0], ))
            db.commit()
    db.close()


# def check_active_vm():
#     ## to do
    

# Schedule the job to run every 1 minute
schedule.every(1).minutes.do(job)
schedule.every(1).minutes.do(synchronize_template_image)
schedule.every(2).minutes.do(shutdown_vm)
# schedule.every(15).minutes.do(check_active_vm)

while True:
    schedule.run_pending()
    time.sleep(1)