# Networks-final-project
In this project we created 4 servers : DHCP server , DNS server , APP server , HTTP redirect server , and a client in Python.

The client is sending a discover packet in broadcast and the DHCP server I created responses with offer packet, the client sends a request packet and the server send an ack packet with the clients IP and the IP of the DNS server I created.

Next, the client sends a request packet directly to the DNS server asking for the APP server IP , the DNS send a response packet with the APP IP.

The client sends an http request to the APP server which forwards the request directly to the HTTP redirect server which returns the pdf file requested.
