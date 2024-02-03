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
1. Modify the file `main.py` to set the environment variables :
  - URL_VNC : URL of the VNC server (ex: https://vnc.insa-cvl.com)
  - URL_VDI : URL of the VDI server (ex: https://vdi.insa-cvl.com)
  - URL_API : URL of the API server (ex: https://api.insa-cvl.com)
  - app.config['SECRET_KEY'] : Secret key of the API 
  - app.config['TOKEN_SECRET_KEY'] : Secret key of the token
  - app.config['SESSION_COOKIE_DOMAIN'] : Domain of the session cookie (ex: insa-cvl.com)
  - app.config['SQLALCHEMY_DATABASE_URI'] : URI of the database (ex : mysql+mysqlconnector://vdi:azerty@vdi-db/vdi)
2. Modify the file `back_openstack.py` to set the environment variables :
  - PRIVATE_NETWORK_ID : ID of the private network
  - USERNAME : Username of the OpenStack user (ex: vdi)
  - PASSWORD : Password of the OpenStack user (ex: vdi)
  - AUTH_URL : URL of the OpenStack authentication (ex: http://172.10.3.60:5000/v3)
  - PROJECT_NAME : Name of the OpenStack project (ex: vdi)
  - USER_DOMAIN_ID : ID of the OpenStack user domain (ex: default)
  - PROJECT_DOMAIN_ID : ID of the OpenStack project domain (ex: default)
3. Create a file `/etc/systemd/system/vdi-api.service` with the following content : 
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
4. Reload the systemd daemon : `systemctl daemon-reload`
5. Enable the service : `systemctl enable vdi-api.service`
6. Start the service : `systemctl start vdi-apî.service`
7. Check the status of the service : `systemctl status vdi-api.service`

### Scheduler
1. Modify the file `scheduler.py` to set the environment variables :
  - DB_HOST : Host of the database (ex: vdi-db)
  - DB_NAME : Name of the database (ex: vdi)
  - DB_USER : User of the database (ex: vdi)
  - DB_PASSWORD : Password of the database (ex: azerty)
2. Modify the file `back_openstack.py` to set the environment variables :
  - PRIVATE_NETWORK_ID : ID of the private network
  - USERNAME : Username of the OpenStack user (ex: vdi)
  - PASSWORD : Password of the OpenStack user (ex: vdi)
  - AUTH_URL : URL of the OpenStack authentication (ex: http://172.10.3.60:5000/v3)
  - PROJECT_NAME : Name of the OpenStack project (ex: vdi)
  - USER_DOMAIN_ID : ID of the OpenStack user domain (ex: default)
  - PROJECT_DOMAIN_ID : ID of the OpenStack project domain (ex: default)
3. Create a file `/etc/systemd/system/vdi-scheduler.service` with the following content :  
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
4. Reload the systemd daemon : `systemctl daemon-reload`
5. Enable the service : `systemctl enable vdi-scheduler.service`
6. Start the service : `systemctl start vdi-scheduler.service`
7. Check the status of the service : `systemctl status vdi-scheduler.service`




## Installation with Docker
### API
1. build the image : `docker build -t vdi-api .` or `docker-compose build` with the docker-compose.yml file
2. run the container : `docker run -it -d -p 5001:5001 --name vdi-api vdi-api` or `docker-compose up -d` with the docker-compose.yml file
```yaml
version: "3.9"
services:
  vdi-api:
    # build: .
    image: vdi-api:latest
    container_name: vdi-api
    restart: always
    ports:
      - 127.0.0.1:5001:5001
    environment:
      - URL_VNC=https://vnc.insa-cvl.com
      - URL_VDI=https://vdi.insa-cvl.com
      - URL_API=https://api.insa-cvl.com
      - DB_HOST=vdi-db
      - DB_NAME=vdi
      - DB_USER=vdi
      - DB_PASSWORD=azerty
      - OPENSTACK_PRIVATE_NETWORK_ID=0d49c37b-7077-4152-985c-f5a00ad20677
      - OPENSTACK_USERNAME=admin
      - OPENSTACK_PASSWORD=3pMrmW899b9y^2kiJa!6#Z#kE%@a2r
      - OPENSTACK_AUTH_URL=http://172.10.3.60:5000/v3
      - OPENSTACK_PROJECT_NAME=admin
      - OPENSTACK_USER_DOMAIN_ID=default
      - OPENSTACK_PROJECT_DOMAIN_ID=default
    depends_on:
      - vdi-db
    links:
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
    # build: .
    image: vdi-scheduler:latest
    container_name: vdi-scheduler
    restart: always
    environment:
      - DB_HOST=vdi-db
      - DB_NAME=vdi
      - DB_USER=vdi
      - DB_PASSWORD=azerty
      - OPENSTACK_PRIVATE_NETWORK_ID=0d49c37b-7077-4152-985c-f5a00ad20677
      - OPENSTACK_USERNAME=admin
      - OPENSTACK_PASSWORD=3pMrmW899b9y^2kiJa!6#Z#kE%@a2r
      - OPENSTACK_AUTH_URL=http://172.10.3.60:5000/v3
      - OPENSTACK_PROJECT_NAME=admin
      - OPENSTACK_USER_DOMAIN_ID=default
      - OPENSTACK_PROJECT_DOMAIN_ID=default
    depends_on:
      - vdi-db
    links:
      - vdi-db
```	
3. check the logs : `docker logs vdi-scheduler` or `docker-compose logs -f`