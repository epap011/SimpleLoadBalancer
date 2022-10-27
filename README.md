# SimpleLoadBalancer
A simple load-balancer implementation that balances the load stemming from different end-users, to a server farm, while taking into account features such as transparency and traffic isolation

Overview of the Setup
The network includes 8 hosts and a switch with an OpenFlow controller (POX). 
The first 4 hosts (h1 to h4) act as clients for a service offered by the hosts h5 to h8,
which act as servers. Each host belongs to a specific service group (e.g., “red” or “blue”); red
clients can be served only by red servers, and blue clients by blue servers. The switch acts as a
load balancer, and balances the flows from the clients towards the servers, taking into account
their respective group membership. The clients are addressing the public IP of the service, and
the switch acts as a transparent proxy between the clients and the actual server. Therefore, it
also rewrites the destination IP targeted by the clients (public service IP) to the chosen server
IP, and vice versa for the reverse communication.

<div style="width:600px; height:600px; text-align: center;">

![Alt text](assets/images/setup_figure.png?raw=true "Figure 1: setup overview")

</div>