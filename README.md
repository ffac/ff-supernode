# Generic Supernode for Freifunk Communities

This ansible script shows how a supernode can be configured with only the basic setup.

It is highly inspired by the ansible scripts from [Freifunk Hannover](https://github.com/freifunkh/ansible).
So a huge thank you!

## Basic Idea

To provide one possible setup how a freifunk domain can be set up, I thought to create a generice documentation of which services are needed and how they should be configured.

Basically, there are two major roles:

* Supernode, containing Wireguard, DHCP, DNS, radvd, BATMAN
* Monitor, containing influxdb, yanic, grafana, map

Of course, if needed, those can each be split into seperate services, by executing a single role per service.
Yet this might configure manual networking between the vms so that, e.g. the DHCP can run somewhere else.

## Features

- multi domain/segments
- configurable batman-iv or batman-v
- wireguard + vxlan + batman
- included basic broker
- synchronizing wireguard public keys through a git repository

## TODO 

- DNS
- monitoring
- ansible secrets
- ...

## Installation


0. install `ansible` & `python-is-python3` on the host - windows is not supported for ansible
1. configure the host vars in sn01.yml according to your freshly set up VM
2. configure group_vars/all/main.yml according to needed count of domains and features
    * the vx.py can be used to generate th VXLAN VNI tag from the gluon domain_seed
    * each domain is run on a seperate port - i only tested with 51820 - so domain 20
3. renew the secrets for ansible in secrets.yml 
    * `wg genkey > privatekey`
    * `wg pubkey < privatekey > publickey`
4. execute `ansible-playbook playbooks/supernode.yml`
5. create a gluon client which connects to your host
    * `uci set wgpeerselector.sn01.public_key='mypublickey'`
    * `uci set wgpeerselector.sn01.endpoint='192.168.0.159:51820'`
6. create a repo with name peers-wg at host `git_addr`
    1. access the generated `.ssh` key from the auto user 
    2. add the key as a readaccess key the peers-wg repo
    3. delete `wait_for_access.lock` to move on
    4. now the allowed keys are pulled from the repo and are update automatically


This allows to create a mail-based-workflow like "send your key to ... to add it" or create a web worker which commits and deletes keys from the repo automatically.

## Secrets

Using ansible-secrets, one can create a file `group_vars/all/secrets.yml` containing all public and private keys per domain like this:

```yml
wireguard_keys: {
  '01': {  # <-- sn
    '10': { # <-- domain/segment
      'secret': 'xxx',
      'public': 'xxx'
    },
    '20': {
      'secret': 'xxx',
      'public': 'xxx'
    }
  }
}
```

Access to the public key is therefore `wireguard_keys['%02d' % sn][domain.id].public`

Then, one can use `ansible-vault encrypt group_vars/all/secrets.yml` and set a password.
The file can then be committed

Finally, ansible needs to ask for the vault-password now using:

```
ansible-playbook --ask-vault-password playbooks/supernode.yml --tags mesh_wireguard
```

### Removing domains

To remove domains, it is suggested to `rm /etc/systemd/network/*` the file.

### MAC-Selection

MAC addresses are not allowed to start with FF - systemd-networkd complains about such interfaces with `Could not join netdev: Provided Ethernet address is not unicast`

## Roles - Supernode

* ff.mesh_batman - configures batman
* ff.ipforward - configures ipforwarding on the host
* ff.wait_for - waits until interfaces are ready
* ff.networkd - configures network based on `networkd_configures` in host_vars
* ff.mesh_wireguard - installs wireguard, vxlan and batman per domain (+ wg_netlink service with https://github.com/ffac/wireguard-vxlan-glue.git)
* ff.mesh_wireguard_remotes_peers_git - clones `peers-wg` repo containing client public keys and updates them regularly through cron
* ff.radv_server - install radvd with the given `mesh_prefix` and IPv6 config
* ff.kea_dhcp4_server - configures internal DHCP server for IPv4 and subnets per domain
* ff.iptables - adds nat config like `iptables -A POSTROUTING -o -j MASQUERADE -t nat` - not needed if uplink is provided through VPN or Freifunk Rheinland
* ff.gw-statuspage - installs a statuspage on the supernode

## Roles - Monitor

* ff.influxdb - installs InfluxDB
* ff.yanic - install Node collector for statistics and meshviewer
* ff.meshviewer - install meshviewer for Freifunk Map
* ff.wgbroker - install broker service where a public key can be entered - also used by Firmware as rest endpoint
* ff.grafana - install grafana with provided templates (TODO)
* ff.promtail & loki & telegraf - host monitoring of the Backbone