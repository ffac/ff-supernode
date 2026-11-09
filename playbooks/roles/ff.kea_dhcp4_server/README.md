# Kea DHCP



## IPv4 setup for DHCP

the client count is (mesh_pool_size * 255)-21 ~= supported client count per sn per segment

using `mesh_pool_size=64` every domain (here: 20) uses the following split range per supernode:

10.20.0.20 -10.20.255.255

while sn01 has the IP: `10.20.0.1`
and gives IPs in the range: `10.20.0.20 - 10.20.63.254`

sn02 has the IP: `10.20.64.1`
and gives IPs in the range: `10.20.64.20 - 10.20.127.254`

sn03 has the IP: `10.20.128.1`
and gives IPs in the range: `10.20.128.20 - 10.20.191.254`

sn04 has the IP: `10.20.192.1`
and gives IPs in the range: `10.20.192.20 - 10.20.255.254`

so each supernode can distribute 16320 private IPv4 addresses to clients.

Using `mesh_pool_size=32` would allow to have 8 supernodes with ~8139 client IP addresses each