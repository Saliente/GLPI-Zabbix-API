import ipaddress
import json
import requests
import urllib3
import base64
from urllib3.exceptions import InsecureRequestWarning

#################################################
#                                               #
#            Variable from Conf File            #
#                                               #
#################################################

with open('config.json', 'r') as confjs:
    file = json.load(confjs)

template_id = file["template"]
group_id = file["groups"]
site = file["sites"]
# Zabbix User
zabbix_authorization = file["auth"]["zabbix_authorization"]
zabbix_snmp_name = file["auth"]["zabbix_snmp_name"]
# GLPI datas
glpi_user = file["auth"]["glpi_user"]
glpi_app_token = file["auth"]["glpi_app_token"]
glpi_status = file["auth"]["glpi_status"]

# Disable TLS Check
urllib3.disable_warnings(InsecureRequestWarning)


#################################################
#                                               #
#                  GLPI Object                  #
#                                               #
#################################################


class Glpi:
    """
    A Class that communicate with GLPI API to inventory by host status
    """

    def __init__(self, url, authorization, app_token):
        self.hosts = []
        self.totalcount_computer = 0
        self.totalcount_networkdevices = 0
        self.totalcount_phone = 0
        self.totalcount_printers = 0
        self.session_token = None
        self.headers = None
        self.status = None
        self.url = url
        self.authorization = str(base64.b64encode(authorization.encode("utf-8")), "utf-8")
        self.app_token = app_token

    def init_session(self):
        """
        Open Session with GLPI API
        :return: Session-token
        """
        init_headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Basic {self.authorization}',
            'App-Token': f'{self.app_token}'
        }

        url = self.url + '/apirest.php/initSession'
        init = requests.get(url=url, headers=init_headers, verify=False)

        # convert init to Json and get de value of 'session_token'
        self.session_token = init.json()['session_token']

        # Generate a header to use on all requests
        self.headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Basic {self.authorization}',
            'Session-Token': f'{self.session_token}',
            'App-Token': f'{self.app_token}'}

    def kill_session(self):
        """
        End API Session communicate
        """
        url = self.url + '/apirest.php/killSession'
        requests.get(url=url, headers=self.headers, verify=False)

    def get_status(self, status):
        self.status = status

    def get_total_devices(self):
        """
        Get the total number of items by each type of device
        :return: insert total count to variable totalcount_'device type'
        """
        # Computer Count
        url = self.url + '/apirest.php/search/Computer?range=0-0'
        response = requests.get(url=url, headers=self.headers, verify=False)
        self.totalcount_computer = int(response.json()["totalcount"])

        # Network Count
        url = self.url + '/apirest.php/search/networkequipment?range=0-0'
        response = requests.get(url=url, headers=self.headers, verify=False)
        self.totalcount_networkdevices = int(response.json()["totalcount"])

        # phone Count
        url = self.url + '/apirest.php/search/phone?range=0-0'
        response = requests.get(url=url, headers=self.headers, verify=False)
        self.totalcount_phone = int(response.json()["totalcount"])

        # Printers Count
        url = self.url + '/apirest.php/search/printer?range=0-0'
        response = requests.get(url=url, headers=self.headers, verify=False)
        self.totalcount_printers = int(response.json()["totalcount"])

    def host_append(self, host):
        """
        Append host data to hosts array
        :param host: a dictionary with host data 'name, states_id, manufacturers_id,
                                                  computertypes_id,
                                                  entities_id, autoupdatesystems_id'
        """
        self.hosts.append(host)

    def get_computer_by_status(self):
        for item in range(self.totalcount_computer):
            url = self.url + f'/apirest.php/Computer/?get_hateoas=false&expand_dropdowns=true&range={item}-{item}'
            response = requests.get(url=url, headers=self.headers, verify=False)
            host = json.loads(response.text)
            if host[0]["states_id"] == self.status:
                item = {
                    "name": host[0]["name"],
                    "manufacturers_id": host[0]["manufacturers_id"],
                    "computertypes_id": host[0]["computertypes_id"],
                    "entities_id": host[0]["entities_id"],
                    "autoupdatesystems_id": host[0]["autoupdatesystems_id"],
                    "computertypes": "Computer"
                }
                self.host_append(item)

    def get_network_by_status(self):
        for item in range(self.totalcount_networkdevices):
            url = self.url + f'/apirest.php/networkequipment/?get_hateoas=false&expand_dropdowns=true&range={item}-{item}'
            response = requests.get(url=url, headers=self.headers, verify=False)
            host = json.loads(response.text)
            if host[0]["states_id"] == self.status:
                item = {
                    "name": host[0]["name"],
                    "states_id": host[0]["states_id"],
                    "manufacturers_id": host[0]["manufacturers_id"],
                    "computertypes_id": host[0]["computertypes_id"],
                    "entities_id": host[0]["entities_id"],
                    "autoupdatesystems_id": host[0]["autoupdatesystems_id"],
                    "computertypes": "networkequipment"
                }
                self.host_append(item)

    def get_phone_by_status(self):
        for item in range(self.totalcount_phone):
            url = self.url + f'/apirest.php/phone/?get_hateoas=false&expand_dropdowns=true&range={item}-{item}'
            response = requests.get(url=url, headers=self.headers, verify=False)
            host = json.loads(response.text)
            if host[0]["states_id"] == self.status:
                item = {
                    "name": host[0]["name"],
                    "states_id": host[0]["states_id"],
                    "manufacturers_id": host[0]["manufacturers_id"],
                    "computertypes_id": host[0]["computertypes_id"],
                    "entities_id": host[0]["entities_id"],
                    "autoupdatesystems_id": host[0]["autoupdatesystems_id"],
                    "computertypes": "phone"
                }
                self.host_append(item)

    def get_printers_by_status(self):
        for item in range(self.totalcount_printers):
            url = self.url + f'/apirest.php/printer/?get_hateoas=false&expand_dropdowns=true&range={item}-{item}'
            response = requests.get(url=url, headers=self.headers, verify=False)
            host = json.loads(response.text)
            if host[0]["states_id"] == self.status:
                item = {
                    "name": host[0]["name"],
                    "states_id": host[0]["states_id"],
                    "manufacturers_id": host[0]["manufacturers_id"],
                    "computertypes_id": host[0]["computertypes_id"],
                    "entities_id": host[0]["entities_id"],
                    "autoupdatesystems_id": host[0]["autoupdatesystems_id"],
                    "computertypes": "printer"
                }
                self.host_append(item)

    def get_all_by_status(self):
        self.get_total_devices()
        self.get_computer_by_status()
        self.get_network_by_status()
        self.get_phone_by_status()
        self.get_printers_by_status()
        return self.hosts

    def get_host_ip(self, computertypes, name):
        url = self.url + f'/apirest.php/search/{computertypes}?criteria[0][link]=AND&criteria[0][itemtype]={computertypes}&criteria[0][field]=1&criteria[0][searchtype]=contains&criteria[0][value]={name}&criteria[1][link]=AND&criteria[1][itemtype]={computertypes}&criteria[1][field]=126&criteria[1][searchtype]=notequals&criteria[1][value]=''&range=0-2&&forcedisplay[0]=1'
        response = requests.get(url=url, headers=self.headers, verify=False)
        return response.json()["data"][0]["126"]


#################################################
#                                               #
#                Zabbix Object                  #
#                                               #
#################################################


class Zabbix:

    def __init__(self, url, user, password):
        self.interface = None
        self.hosts = []
        self.session_token = None
        self.snmp_name = None
        self.url = url
        self.user = user
        self.passwd = password

    def init_session(self):
        body = {
            "jsonrpc": "2.0",
            "method": "user.login",
            "params": {
                "user": self.user,
                "password": self.passwd
            },
            "id": 1
        }
        response = requests.post(self.url, json=body, verify=False)
        self.session_token = response.json()['result']

    def get_all_host(self):
        body = {
            "jsonrpc": "2.0",
            "method": "host.get",
            "params": {
                "output": ["name"]
            },
            "auth": f'{self.session_token}',
            "id": 1
        }

        response = requests.post(url=self.url, json=body)
        # Get hosts of Zabbix
        hosts = response.json()["result"]
        for item in hosts:
            item = item["name"]
            self.hosts.append(item)

        return self.hosts

    def host_create(self, name, interface_name, template, group, ip_address):
        if interface_name == self.snmp_name:
            self.interface = {
                "type": 2,
                "main": 1,
                "useip": 1,
                "ip": f'{ip_address}',
                "dns": "",
                "port": "161"
            }
        else:
            self.interface = {
                "type": 1,
                "main": 1,
                "useip": 1,
                "ip": f'{ip_address}',
                "dns": "",
                "port": "10050"
            }
            body = {
                "jsonrpc": "2.0",
                "method": "host.create",
                "params": {
                    "host": f'{name}',
                    "interfaces": [self.interface],
                    "groups": [{
                        "groupid": f'{group}'
                    }],
                    "templates": [{
                        "templateid": f'{template}'
                    }],
                },
                "id": 1,
                "auth": f'{self.session_token}'
            }

            r = requests.post(url=self.url, json=body)
            print(r.text)

    def get_snmp_name(self, name_of_snmp):
        self.snmp_name = name_of_snmp


#################################################
#                                               #
#               Script to inventory             #
#                                               #
#################################################


zabbix = Zabbix(url=site["zabbix"], user=zabbix_authorization[0], password=zabbix_authorization[1])
zabbix.init_session()
zabbix_hosts = zabbix.get_all_host()
zabbix.get_snmp_name(zabbix_snmp_name)

glpi = Glpi(url=site["glpi"], authorization=glpi_user, app_token=glpi_app_token)
glpi.init_session()
glpi.get_status(glpi_status)
inventory = glpi.get_all_by_status()

"""
For each device on GLPI with status == glpi_status variable Will be inventoried
If device on inventory not be on Zabbix, create a Zabbix host
validation is done based on the device name   
"""
for equipment in inventory:
    if equipment["name"] not in zabbix_hosts:
        net_interfaces = glpi.get_host_ip(equipment["computertypes"], name=equipment["name"])
        for ip in net_interfaces:
            if (ipaddress.ip_network(ip).version == 4) and (ipaddress.ip_address(ip).is_loopback is False):
                hostname = equipment["name"]
                interface = equipment["autoupdatesystems_id"]
                pctype = template_id[equipment["computertypes_id"]]
                entity = group_id[equipment["entities_id"][20::]]
                zabbix.host_create(name=hostname, interface_name=interface, template=pctype, group=entity, ip_address=ip)


glpi.kill_session()
