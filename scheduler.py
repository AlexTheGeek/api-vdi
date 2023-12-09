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
            db.commit()


    for template in templates_db:
        if template not in images_openstack:
            cursor.execute("DELETE FROM template WHERE name = %s", (template))
            db.commit()
            
    db.close()

            
    
    
    
    

# Schedule the job to run every 1 minute
schedule.every(1).minutes.do(job)
schedule.every(1).minutes.do(synchronize_template_image)

while True:
    schedule.run_pending()
    time.sleep(1)