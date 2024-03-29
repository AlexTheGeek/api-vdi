FROM python:3.11.4-bookworm

RUN apt update

RUN apt install python3-openstacksdk -y 
# python3-openstackclient

RUN pip install gunicorn==20.1.0 Flask==3.0.0 Flask-API==1.1 Flask-Cors==4.0.0 Flask-Login==0.6.3 Flask-Migrate==4.0.5 Flask-SQLAlchemy==3.1.1 argon2-cffi==21.1.0 requests==2.28.1 mysql-connector-python==8.2.0 defusedxml==0.7.1 
# python-openstackclient==6.0.0 openstacksdk==0.101.0


RUN mkdir /api
WORKDIR /api

COPY entrypoint.sh .
COPY main.py .
COPY back_openstack.py .

RUN mkdir -p /api/static
COPY ./static/robots.txt /api/static/robots.txt

# Partie variable d'environnement URLs
ENV URL_VNC=https://vnc.insa-cvl.com
ENV URL_VDI=https://vdi.insa-cvl.com
ENV URL_API=https://api.insa-cvl.com
ENV URL_API_CAS=api.insa-cvl.com

# Partie variable d'environnement API
ENV FLASK_SECRET_KEY=secret
ENV FLASK_TOKEN_SECRET_KEY=secret
ENV DOMAIN=insa-cvl.com

# Partie variable d'environnement DB
ENV DB_HOST=vdi-db
ENV DB_NAME=vdi
ENV DB_USER=vdi
ENV DB_PASSWORD=azerty

# Partie variable d'environnement OpenStack
ENV OPENSTACK_PRIVATE_NETWORK_ID=0d49c37b-7077-4152-985c-f5a00ad20677
ENV OPENSTACK_USERNAME=vdi
ENV OPENSTACK_PASSWORD=vdi
ENV OPENSTACK_AUTH_URL=http://127.0.0.1:5000/v3
ENV OPENSTACK_PROJECT_NAME=vdi
ENV OPENSTACK_USER_DOMAIN_ID=default
ENV OPENSTACK_PROJECT_DOMAIN_ID=default


EXPOSE 5001

CMD ["/bin/bash", "entrypoint.sh"]
