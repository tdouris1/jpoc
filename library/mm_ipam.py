#!/usr/bin/python

DOCUMENTATION = """
---
module: mm_ipam
version_added: "2.2"
author: "James Mighion"
short_description: Claim or release an IP address from Men & Mice
description:
  - Uses the mmJSONClient provided by Men & Mice to connect to a
    server, handle the session, and return JSON objects. This module
    provides a way to change an IPAMRecord in Men & Mice so that
    either an IP is claimed from a given CIDR or a given IP is
    claimed or released. An error is returned if the given IP is
    already claimed, there's no available IP left in the given
    range, or the given IP or CIDR are not valid. This module edits
    the property C(claimed) on a Men & Mice IPAMRecord.
options:
  action:
    description:
      - Either C(claim) to claim an available IP or C(release) to
        release an IP.
    required: true
    default: null
    choices: ['claim', 'release']
  address:
    description:
      - A valid IP or CIDR. Can be either IPv4 or IPv6. Shortend IPv4
        addresses are not allowed.
    required: true
    default: null
  username:
    description:
      - Username to authenticate to the server.
    required: true
    default: null
  password:
    description:
      - Password to authenticate to the server.
    required: true
    default: null
  server:
    description:
      - Men & Mice central server.
    required: true
    default: null
  proxy:
    description:
      - Men & Mice proxy server. Typically for a seperate API/Web Service server.
    required: true
    default: null

requirements:
  - mmJSONClient from Men & Mice. https://www.menandmice.com/resources/json-rpc/ . https://docs.menandmice.com/download/attachments/4849733/mmJSONClient-1.0.0.tar.gz?api=v2
"""

EXAMPLES = """
- mm_ipam:
    action: claim
    address: 10.50.80.50
    username: user
    password: password
    server: central.example.com
    proxy: webservice.example.com

- mm_ipam:
    action: claim
    address: 10.50.80.50/30
    username: user
    password: password
    server: central.example.com
    proxy: webservice.example.com

- mm_ipam:
    action: claim
    address: "2001:4898:4800::1"
    username: user
    password: password
    server: central.example.com
    proxy: webservice.example.com

- mm_ipam:
    action: claim
    address: "2001:4898:4800::/44"
    username: user
    password: password
    server: central.example.com
    proxy: webservice.example.com

- mm_ipam:
    action: release
    address: 10.50.80.50
    username: user
    password: password
    server: central.example.com
    proxy: webservice.example.com

- mm_ipam:
    action: release
    address: "2001:4898:4800::1"
    username: user
    password: password
    server: central.example.com
    proxy: webservice.example.com
"""

RETURN = """
address:
  description: The newly claimed address
  returned: Only when action is `claim`
  type: string
  sample: 10.50.80.50
"""

from ansible.module_utils.basic import AnsibleModule
import mmJSONClient
import socket

# TODO move these helper methods to a module_util. In Ansible 2.3 we can have this at the
# root of the repo for ease of management.
def set_properties(module, client, ref, properties, result):
    if not module.check_mode:
        client.SetProperties(ref=ref,properties=properties)
    result['changed'] = True

def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        # Not allowing shortened addresses like '127.1'. Must be dotted quad.
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True

def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False

    return True

def is_valid_cidr(address):
    if '/' in address:
        ip, mask = address.split('/')
        if is_valid_ipv4_address(ip):
            if int(mask) > 32:
                return False
        elif is_valid_ipv6_address(ip):
            if int(mask) > 128:
                return False
        else:
            return False

        return True

    return False

def main():
    module = AnsibleModule(
        argument_spec = dict(
            action    = dict(required=True, choices=['claim', 'release']),
            address   = dict(required=True, type='str'),
            username  = dict(required=True, type='str'),
            password  = dict(required=True, no_log=True, type='str'),
            proxy     = dict(required=True, type='str'),
            server    = dict(required=True, type='str')
        ),
        supports_check_mode=True
    )

    client = mmJSONClient.JSONClient()
    client.Login(proxy=module.params['proxy'],server=module.params['server'],username=module.params['username'],password=module.params['password'])

    result = {'changed': False}

    try:
        if is_valid_cidr(module.params['address']):
            available_address = client.GetNextFreeAddress(rangeRef=module.params['address'])
            if available_address:
                address = available_address['address']
            else:
                module.fail_json(msg="No available address in the given range : %s" % module.params['cidr'])
        elif is_valid_ipv4_address(module.params['address']) or is_valid_ipv6_address(module.params['address']):
            address = module.params['address']
        else:
            module.fail_json(msg="Address %s is not a valid CIDR or IP address" % module.params['address'])

        ipamRecord = client.GetIPAMRecord(addrRef=address)['ipamRecord']

        if module.params['action'] == 'claim':
            if ipamRecord['state'].lower() != 'free':
                module.fail_json(msg="Address is already claimed.")

            properties = [{'name': 'claimed', 'value': 'true'}]
            set_properties(module, client, ipamRecord['addrRef'], properties, result)
            result['address'] = address
        elif ipamRecord['state'].lower() == 'claimed':
            properties = [{'name': 'claimed', 'value': 'false'}]
            set_properties(module, client, ipamRecord['addrRef'], properties, result)
    except Exception as err:
        module.fail_json(msg=str(err))

    module.exit_json(**result)

if __name__ == '__main__':
    main()
