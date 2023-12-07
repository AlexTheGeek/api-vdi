import schedule
import time
import mysql.connector
import back_openstack as openstack

def job():
    print("Job is running...")

# Schedule the job to run every 1 minute
schedule.every(1).minutes.do(job)

while True:
    schedule.run_pending()
    time.sleep(1)