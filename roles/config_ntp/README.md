config_ntp
=========

This role configures the NTP settings on a device.

Role Variables
--------------

A description of the settable variables for this role should go here, including any variables that are in defaults/main.yml, vars/main.yml, and any variables that can/should be set via parameters to the role. Any variables that are read from other roles and/or the global scope (ie. hostvars, group vars, etc.) should be mentioned here as well.
The `ntp_peering_key` variable is the NTP key for the hosts. This is defaulted to point to the vaulted version `vault_trap_string`.
The variables `ntp_service_ipv4` and `ntp_service_ipv6` are used to set the NTP servers. The default values are in the default/main.yml file.
The `ntp_source` is a used to default the NTP source to something if the `mgmt_interface_name` isn't found or supplied.
`mgmt_interface_name` is parsed out of the hosts in the network_facts role.
The `cli` variable holds the credentials and transport type to connect to the device.
The `device_os` variable is the type of device OS that the current host is. We use this to decide which tasks and templates to run since each OS can have OS specific commands. This should be coming from a group var.


Dependencies
------------

network_facts role
