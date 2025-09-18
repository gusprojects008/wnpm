# NET_CONFIG

## Network IP Address Configurator for Machine

### Tries to assign IP addresses from the network to which the machine is connected, through:
- **DHCP**: Sends a DHCP Request packet to the Local DHCP Server and waits for a response. if there is a response, an address is assigned to the machine. if no response is received, an analysis of local network traffic is performed. 
- **Network Traffic Analysis**: Through of managed interface connected at network, is performed a analysis of traffic of packets, looking for address IP or subnetmask used to local devices, case not found, the program is provided a interface for the user set the IP address manually.
- **Manually if the user prefers**: The user configure the IP address manually, for this he must be know the CIDR(Classless Inter-Domain Routing) or subnet in that is. You can take a device connected the network and see the subnet in which he is, or see the local IP address that he uses.

***This program is made for educational purposes and studies about structuring of packets data, sockets, protocols and traffic analysis, packets of network, interaction with linux kernel through netlink protocol, IP address and types.***
