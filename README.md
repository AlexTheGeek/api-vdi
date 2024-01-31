# API VDI

## Description
This project is an API to manage the VDI infrastructure running on OpenStack of the INSA CVL.
This API can manage the following elements :
- Users
- Groups
- VMs
- Templates

## Installation
### Requirements
1. Linux : Ubuntu 20.04, Debian 12
2. Python 
3. Pip or Pipx : you can even create a virtual environment to run those scripts
4. Create a user vdi with the home directory `/home/vdi`
5. Create a folder `/home/vdi/VDI` for the API and and clone this repository in it  
    5.1. `mkdir -p /home/vdi/VDI-API`  
    5.2. `cd /home/vdi/VDI-API`  
    5.3. `git clone https://github.com/AlextTheGeek/api-vdi.git`  
6. Install the requirements : `pip install -r requirements.txt`
7. Create a folder /var/log/VDI/API for the logs of the API : `mkdir -p /var/log/VDI/API`  
    7.1. Set the rights of the user who runs the API (here vdi) on this folder : `chown -R vdi:vdi /var/log/VDI/API`  
8. Create a folder /var/log/VDI/Scheduler for the logs of the scheduler : `mkdir -p /var/log/VDI/Scheduler`  


### API
#### Systemd
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
#### Systemd
To run the scheduler as a service, you need to create a systemd service like the example below in the file /etc/systemd/system/vdi-scheduler.service  
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