import base64
from openstack import connection as connexion
import os

#Constants 
USERNAME = os.getenv('OPENSTACK_USERNAME')
PASSWORD = os.getenv('OPENSTACK_PASSWORD')
#Network Constants
PRIVATE_NETWORK_ID = os.getenv('OPENSTACK_PRIVATE_NETWORK_ID')
# EXTERNAL_NETWORK_ID = os.getenv('')
AUTH_URL = os.getenv('OPENSTACK_AUTH_URL')
#Openstack Constants
PROJECT_NAME = os.getenv('OPENSTACK_PROJECT_NAME')
USER_DOMAIN_ID = os.getenv('OPENSTACK_USER_DOMAIN_ID')
PROJECT_DOMAIN_ID = os.getenv('OPENSTACK_PROJECT_DOMAIN_ID')

conn = connexion.Connection(auth_url=AUTH_URL, project_name=PROJECT_NAME, username=USERNAME, user_domain_id=USER_DOMAIN_ID, project_domain_id=PROJECT_DOMAIN_ID, password=PASSWORD)

"""
Unused functions
def get_infos(conn):
    for server in conn.compute.servers():
        print(f"Server name : {server.name}\n")

    for image in conn.compute.images():
        print("Image name : " + image.name)

def get_flavor(conn):
    for flavor in conn.compute.flavors():
        print("Flavor name : " + flavor.name)

def get_network(conn):
    print("--------------------")
    for network in conn.network.networks():
        print("Network name : " + network.name)
        print("Network id : " + network.id)
        print("Network status : " + network.status)
        print("--------------------")

### Admin only
def get_endpoint(conn):
    for endpoint in conn.identity.endpoints():
        print(f"Endpoint name : {endpoint.name}")

def get_projects(conn):
    for project in conn.identity.projects():
        print(f"Project name : {project.name}")

def get_users(conn):
    for user in conn.identity.users():
        print(f"User name : {user.name}")

def get_floating_IPs(conn):
    for ip in conn.network.ips():
        print(f"IP name : {ip.name}")

    #create a new floating ip (fonctionne)
    # ip = conn.network.create_ip(floating_network_id=EXTERNAL_NETWORK_ID)

def create_floating_IP(conn):
    ip = conn.network.create_ip(floating_network_id=EXTERNAL_NETWORK_ID)
    return ip.floating_ip_address     

def remove_floating_IP(conn, ip:str):
    conn.network.delete_ip(ip)
"""

#Used functions

def get_image(conn):
    images = []
    for image in conn.compute.images():
        images.append(image.name)
    return images

def get_infos_project(conn, print_infos=True):
    project = conn.identity.find_project("admin")
    nova_client = conn.compute
    quota_info = nova_client.get(f"/os-quota-sets/{project.id}?usage=True").json()['quota_set']
    usage_info = nova_client.get(f"/os-simple-tenant-usage/{project.id}").json()['tenant_usage']

    quota_ram = quota_info['ram']
    quota_servers = quota_info['instances']
    quota_vcpu = quota_info['cores']

    quotas = [quota_servers, quota_ram, quota_vcpu]
    servers = nova_client.servers(details=True, project_id=project.id)

    total_ram_used = 0
    total_vcpu_used = 0
    # total_disk_used = 0
    nb_servers = 0

    for server in servers:
        total_ram_used += server.to_dict()['flavor']['ram']
        total_vcpu_used += server.to_dict()['flavor']['vcpus']
        # total_disk_used += server.to_dict()['flavor']['disk']
        nb_servers += 1

    used = [nb_servers, total_ram_used, total_vcpu_used]
    if print_infos:
        print("Project Name:", project.name)
        print("NB Servers:", nb_servers)
        print("Total RAM Used (MB):", total_ram_used)
        print("Total vCPU Used:", total_vcpu_used)
        # print("Total Disk Used:", total_disk_used)
    return [quotas, used]

def get_console_url(conn, vm_name:str):
    server = conn.compute.find_server(vm_name)
    object_url = server.get_console_url(conn.compute, "novnc")
    return object_url['url']

def get_status_server(conn, vm_name:str):
    server = conn.compute.find_server(vm_name)
    instance = conn.compute.get_server(server['id'])
    status = instance.to_dict()['status']
    vm_state = instance.to_dict()['power_state']
    return vm_state, status

def create_instance(conn, vm_name:str, vm_image:str):
    image = conn.compute.find_image(f"{vm_image}")
    flavor = conn.compute.find_flavor("vdi")
    template_ram = flavor.ram
    template_vcpu = flavor.vcpus
    template_disk = flavor.disk
    # Get Quotas and Used
    quota, used = get_infos_project(conn, print_infos=False)
    if (used[0] < quota[0]) and (template_ram <= quota[1]-used[1]) and (template_vcpu <= quota[2]-used[2]):
        userdata = """#!/bin/bash\necho 'INSTALL VDI'\n"""
        server = conn.compute.create_server(
            name=vm_name,
            image_id=image.id,
            flavor_id=flavor.id,
            networks=[{"uuid": PRIVATE_NETWORK_ID}],
            user_data=base64.b64encode(userdata.encode("utf-8")).decode("utf-8"),
        )
        conn.compute.wait_for_server(server)
        return 0
    else:
        return 1

def remove_instance(conn, name:str):
    server = conn.compute.find_server(name)
    conn.compute.delete_server(server)

def remove_all_instances(conn):
    for server in conn.compute.servers():
        conn.compute.delete_server(server)



