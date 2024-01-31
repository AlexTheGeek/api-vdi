FROM python:3.11.2-bullseye

RUN apt update

RUN pip install python-openstackclient==6.0.0

RUN mkdir /api
WORKDIR /api

COPY entrypoint.sh .
COPY main.py .
COPY back_openstack.py .

RUN mkdir -p /api/static
COPY robots.txt /api/static/robots.txt

# Partie variable d'environnement URLs
ENV URL_VNC="https://vnc.insa-cvl.com/"
ENV URL_VDI="https://vdi.insa-cvl.com/"
ENV URL_API="https://api.insa-cvl.com/"

# Partie variable d'environnement API


# Partie variable d'environnement DB
ENV DB_HOST="127.0.0.1"
ENV DB_NAME="vdi4"
ENV DB_USER="root"
ENV DB_PASSWORD="azerty"

# Partie variable d'environnement OpenStack
ENV OPENSTACK_PRIVATE_NETWORK_ID="0d49c37b-7077-4152-985c-f5a00ad20677"
ENV OPENSTACK_USERNAME="admin"
ENV OPENSTACK_PASSWORD="3pMrmW899b9y^2kiJa!6#Z#kE%@a2r"
ENV OPENSTACK_AUTH_URL="http://172.10.3.60:5000/v3"
ENV OPENSTACK_PROJECT_NAME="admin"
ENV OPENSTACK_USER_DOMAIN_ID="default"
ENV OPENSTACK_PROJECT_DOMAIN_ID="default"


EXPOSE 5001

CMD ["/bin/bash", "entrypoint.sh"]