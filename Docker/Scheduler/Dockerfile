FROM python:3.11.2

RUN pip install schedule==1.2.1 mysql-connector-python==8.2.0 python-openstackclient==6.0.0

RUN mkdir /scheduler
WORKDIR /scheduler

# Partie variable d'environnement DB
ENV DB_HOST=vdi-db
ENV DB_NAME=vdi
ENV DB_USER=root
ENV DB_PASSWORD=azerty

# Partie variable d'environnement OpenStack
ENV OPENSTACK_PRIVATE_NETWORK_ID=0d49c37b-7077-4152-985c-f5a00ad20677
ENV OPENSTACK_USERNAME=vdi
ENV OPENSTACK_PASSWORD=vdi
ENV OPENSTACK_AUTH_URL=http://127.0.0.1:5000/v3
ENV OPENSTACK_PROJECT_NAME=vdi
ENV OPENSTACK_USER_DOMAIN_ID=default
ENV OPENSTACK_PROJECT_DOMAIN_ID=default

COPY scheduler.py .
COPY back_openstack.py .

CMD ["python", "scheduler.py"]