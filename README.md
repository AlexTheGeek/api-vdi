# API VDI

## Description
This project is an API to manage the VDI infrastructure running on OpenStack of the INSA CVL.
This API can manage the following elements :
- Users
- Groups
- VMs
- Templates

## Installation without Docker
### Requirements
1. Linux : Ubuntu 20.04, Debian 11,12
2. Database : Mariadb or MySQL
3. Python 3.11.2
4. Pip or Pipx : you can even create a virtual environment to run those scripts
5. Create a user vdi with the home directory `/home/vdi`
6. Create a folder `/home/vdi/VDI-API` for the API and and clone this repository in it  
    6.1. `mkdir -p /home/vdi/VDI-API`  
    6.2. `cd /home/vdi/VDI-API`  
    6.3. `git clone https://github.com/AlextTheGeek/api-vdi.git`  
7. Install the requirements : `pip install -r requirements.txt`
8. Create a folder /var/log/VDI/API for the logs of the API : `mkdir -p /var/log/VDI/API`  
    8.1. Set the rights of the user who runs the API (here vdi) on this folder : `chown -R vdi:vdi /var/log/VDI/API`  
9. Create a folder /var/log/VDI/Scheduler for the logs of the scheduler : `mkdir -p /var/log/VDI/Scheduler`  


### API
To run the API as a service, you need to create a systemd service like the example below in the file /etc/systemd/system/vdi-api.service  
```bash
[Unit]
Description=Gunicorn instance to serve API VDI
After=network.target

[Service]
User=vdi
Group=vdi
WorkingDirectory=/path/to/the/folder # Path to the folder containing the wsgi.py file
Environment="PATH=/home/vdi/.local/bin" # Necessary to find gunicorn if you installed it with pipx
ExecStart=/home/vdi/.local/bin/gunicorn --access-logfile /var/log/VDI/API/access.log --error-logfile /var/log/VDI/API/error.log --workers 3 --bind 0.0.0.0:5001 main:app # You need to check 
Restart=always

[Install]
WantedBy=multi-user.target
```

### Scheduler
1. Create a file `/etc/systemd/system/vdi-app.service` with the following content :  
    ```bash
    [Unit]
    Description=Python VDI Scheduler Service
    After=network.target

    [Service]
    User=vdi
    Group=vdi
    ExecStart=/usr/bin/python3 /path/to/the/folder/scheduler.py
    Restart=always

    [Install]
    WantedBy=multi-user.target
    ```
2. Reload the systemd daemon : `systemctl daemon-reload`
3. Enable the service : `systemctl enable vdi-app.service`
4. Start the service : `systemctl start vdi-app.service`
5. Check the status of the service : `systemctl status vdi-app.service`




## Installation with Docker
### Requirements

### API
1. build the image : `docker build -t vdi-api .` or `docker-compose build` with the docker-compose.yml file
2. run the container : `docker run -it -d -p 5001:5001 --name vdi-api vdi-api` or `docker-compose up -d` with the docker-compose.yml file
```yaml
version: "3.9"
services:
  vdi-api:
    image: vdi-api:latest
    container_name: vdi-api
    restart: always
    ports:
      - 5001:5001
    environment:
      - URL_VNC="https://vnc.insa-cvl.com/"
      - URL_VDI="https://vdi.insa-cvl.com/"
      - URL_API="https://api.insa-cvl.com/"
      - DB_HOST="vdi-db"
      - DB_NAME="vdi"
      - DB_USER="vdi"
      - DB_PASSWORD="azerty"
      - OPENSTACK_PRIVATE_NETWORK_ID="0d49c37b-7077-4152-985c-f5a00ad20677"
      - OPENSTACK_USERNAME="admin"
      - OPENSTACK_PASSWORD="3pMrmW899b9y^2kiJa!6#Z#kE%@a2r"
      - OPENSTACK_AUTH_URL="http://172.10.3.60:5000/v3"
      - OPENSTACK_PROJECT_NAME="admin"
      - OPENSTACK_USER_DOMAIN_ID="default"
      - OPENSTACK_PROJECT_DOMAIN_ID="default"
    depends_on:
      - vdi-db
```	
3. check the logs : `docker logs vdi-api` or `docker-compose logs -f`


### Scheduler
1. build the image : `docker build -t vdi-scheduler .` or `docker-compose build` with the docker-compose.yml file
2. run the container : `docker run -it -d --name vdi-scheduler vdi-scheduler` or `docker-compose up -d` with the docker-compose.yml file
```yaml
version: "3.9"
services:
    vdi-scheduler:
    image: vdi-scheduler:latest
    container_name: vdi-scheduler
    restart: always
    environment:
        - DB_HOST="vdi-db"
        - DB_NAME="vdi"
        - DB_USER="vdi"
        - DB_PASSWORD="azerty"
        - OPENSTACK_PRIVATE_NETWORK_ID="0d49c37b-7077-4152-985c-f5a00ad20677"
        - OPENSTACK_USERNAME="admin"
        - OPENSTACK_PASSWORD="3pMrmW899b9y^2kiJa!6#Z#kE%@a2r"
        - OPENSTACK_AUTH_URL="http://172.10.3.60:5000/v3"
        - OPENSTACK_PROJECT_NAME="admin"
        - OPENSTACK_USER_DOMAIN_ID="default"
        - OPENSTACK_PROJECT_DOMAIN_ID="default" 
    depends_on:
        - vdi-db
```	
3. check the logs : `docker logs vdi-scheduler` or `docker-compose logs -f`