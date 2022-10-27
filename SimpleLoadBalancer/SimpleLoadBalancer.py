###################################
# @Author: Efthymios Papageorgiou #
# Version: 1                      #
# Load Balancer                   #
###################################
from pox.core import core
from pox.openflow import *
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
log = core.getLogger()
import time
import random
import json # addition to read configuration from file

class SimpleLoadBalancer(object):

    # initialize SimpleLoadBalancer class instance
    def __init__(self, lb_mac = None, service_ip = None, 
                 server_ips = [], user_ip_to_group = {}, server_ip_to_group = {}):
        
        # add the necessary openflow listeners
        core.openflow.addListeners(self)
 
        # set class parameters
        self.lb_mac                = lb_mac
        self.service_ip            = service_ip
        self.server_ips            = server_ips
        self.user_ip_to_group      = user_ip_to_group
        self.server_ip_to_group    = server_ip_to_group
        self.server_ips_info_table = {} #this dictionary stores the mac address and the port of a server ip
        self.client_ips_info_table = {} #this dictionary stores the mac address and the port of a client ip


    # respond to switch connection up event
    def _handle_ConnectionUp(self, event):
        self.connection = event.connection
        
        for server_ip in self.server_ips:
            self.send_proxied_arp_request(self.connection, server_ip)


    # update the load balancing choice for a certain client
    def update_lb_mapping(self, client_ip):
        color_group = self.user_ip_to_group[client_ip]
        same_group_server_ips = {}
        if color_group == 'red':
            same_group_server_ips = [key for key,value in self.server_ip_to_group.items() if value == 'red']
        elif color_group == 'blue':
            same_group_server_ips = [key for key,value in self.server_ip_to_group.items() if value == 'blue']

        server_ip = same_group_server_ips[random.randint(0, len(same_group_server_ips)-1)]

        return server_ip
    

    # send ARP reply "proxied" by the controller (on behalf of another machine in network)
    def send_proxied_arp_reply(self, packet, connection, outport, requested_mac):
        arp_reply          = arp()
        arp_reply.opcode   = arp.REPLY
        arp_reply.hwsrc    = self.lb_mac
        arp_reply.hwdst    = packet.payload.hwsrc
        arp_reply.protosrc = packet.payload.protodst
        arp_reply.protodst = packet.payload.protosrc

        ether         = ethernet()
        ether.type    = ethernet.ARP_TYPE
        ether.src     = self.lb_mac
        ether.dst     = packet.src
        ether.payload = arp_reply

        msg      = of.ofp_packet_out()
        msg.data = ether.pack()
        msg.actions.append(of.ofp_action_output(port = outport))
        
        connection.send(msg)


    # send ARP request "proxied" by the controller (so that the controller learns about another machine in network)
    def send_proxied_arp_request(self, connection, ip):
        arp_request          = arp()
        arp_request.opcode   = arp.REQUEST
        arp_request.hwsrc    = self.lb_mac
        arp_request.hwdst    = ETHER_BROADCAST
        arp_request.protosrc = self.service_ip
        arp_request.protodst = ip

        ether         = ethernet()
        ether.type    = ethernet.ARP_TYPE
        ether.src     = self.lb_mac
        ether.dst     = ETHER_BROADCAST
        ether.payload = arp_request

        msg      = of.ofp_packet_out()
        msg.data = ether.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        
        connection.send(msg)


    # install flow rule from a certain client to a certain server
    def install_flow_rule_client_to_server(self, connection, outport, client_ip, server_ip, buffer_id=of.NO_BUFFER):
        
        client_ip = IPAddr.__str__(client_ip)
        server_ip = IPAddr.__str__(server_ip)

        #if terminate pox and start it again, then there is high posssibility for:
        #Client pings service, but controller handles and icmp packet first, instead of arp.
        #If that happens controller will have an error at line 117
        #If we clean the mininet topology after the pox's termination, we will never have this bug
        while client_ip not in self.client_ips_info_table:
            print('\nBug: IP packet reached controller before Arp packet\n')
            time.sleep(3)
            continue

        ofp_match         = of.ofp_match()
        ofp_match.dl_type = 0x800
        ofp_match.in_port = self.client_ips_info_table[client_ip]['port']
        ofp_match.nw_src  = client_ip
        ofp_match.nw_dst  = self.service_ip

        actions = []
        actions.append(of.ofp_action_nw_addr.set_src(client_ip))
        actions.append(of.ofp_action_dl_addr.set_src(self.lb_mac))
        actions.append(of.ofp_action_dl_addr.set_dst(self.server_ips_info_table[server_ip]['mac']))
        actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        actions.append(of.ofp_action_output(port = outport))

        msg              = of.ofp_flow_mod()
        msg.idle_timeout = 10
        msg.buffer_id    = buffer_id
        msg.match        = ofp_match
        msg.actions      = actions
        
        connection.send(msg)


    # install flow rule from a certain server to a certain client
    def install_flow_rule_server_to_client(self, connection, outport, server_ip, client_ip, buffer_id=of.NO_BUFFER):
        
        client_ip = IPAddr.__str__(client_ip)
        server_ip = IPAddr.__str__(server_ip)

        ofp_match         = of.ofp_match()
        ofp_match.dl_type = 0x800
        ofp_match.nw_src  = server_ip
        ofp_match.nw_dst  = client_ip

        actions = []
        actions.append(of.ofp_action_nw_addr.set_src(self.service_ip))
        actions.append(of.ofp_action_dl_addr.set_src(self.lb_mac))
        actions.append(of.ofp_action_dl_addr.set_dst(self.client_ips_info_table[client_ip]['mac']))
        actions.append(of.ofp_action_nw_addr.set_dst(client_ip))
        actions.append(of.ofp_action_output(port = outport))

        msg              = of.ofp_flow_mod()
        msg.idle_timeout = 10
        msg.buffer_id    = buffer_id
        msg.match        = ofp_match
        msg.actions      = actions
        
        connection.send(msg)


    # main packet-in handling routine
    def _handle_PacketIn(self, event):
        packet     = event.parsed
        connection = event.connection
        inport     = event.port

        print("\n[PackerIN event has been occured]\n")
        if packet.type == packet.ARP_TYPE:
            print("> ARP type packet has been received\n")
            arp_packet = packet.payload
            if arp_packet.opcode == arp.REQUEST:
                print("> packet info\n    arp-type: request\n    src_ip  : {}\n    dest_ip : {}\n    src_mac : {}\n    dest_mac: {}\n"
                .format(arp_packet.protosrc, arp_packet.protodst, arp_packet.hwsrc, arp_packet.hwdst))

                #case where a client and only a client, asks for service's mac
                if arp_packet.protodst == self.service_ip:
                    if arp_packet.protosrc not in self.server_ips:
                        self.client_ips_info_table[IPAddr.__str__(arp_packet.protosrc)] = {'mac': EthAddr.__str__(packet.src), 'port':inport}
                        self.send_proxied_arp_reply(packet, connection, inport, self.lb_mac)
                
                #case where a server and only a server, asks for client's mac
                if arp_packet.protosrc in self.server_ips:
                    #a server should only asks for client ip
                    if arp_packet.protodst not in self.server_ips:
                        #case where the mac of the requested ip is already stored at the dictionary
                        if IPAddr.__str__(arp_packet.protodst) in self.client_ips_info_table:
                            self.send_proxied_arp_reply(packet, connection, inport, self.lb_mac)
                        else:
                            print('> Unexpected situation')

            elif arp_packet.opcode == arp.REPLY:
                print("> packet info\n    arp-type: reply\n    src_ip  : {}\n    dest_ip : {}\n    src_mac : {}\n    dest_mac: {}\n"
                .format(arp_packet.protosrc, arp_packet.protodst, arp_packet.hwsrc, arp_packet.hwdst))

                self.server_ips_info_table[IPAddr.__str__(arp_packet.protosrc)] = {'mac': EthAddr.__str__(packet.src), 'port':inport}
        
        elif packet.type == packet.IP_TYPE:
            print("> IP type packet has been received\n")
            src_ip  = packet.payload.srcip
            dest_ip = packet.payload.dstip 

            print("> packet info\n    src_ip  : {}\n    dest_ip : {}\n"
                .format(src_ip, dest_ip))

            #a client should only interact with the service, otherwise drop the packet
            if src_ip not in self.server_ips and dest_ip != self.service_ip:
                print('>[Error]: A client can only interact with the service!')
                return

            #a server cannot ping the service
            if src_ip in self.server_ips and dest_ip == self.service_ip:
                print('>[Error]: A server cannot ping the service!')
                return
            
            if src_ip in self.server_ips:
                print('> installing flow rule: server -> client..')               
                port_to_client = self.client_ips_info_table[IPAddr.__str__(dest_ip)]['port']
                self.install_flow_rule_server_to_client(connection, port_to_client, src_ip, dest_ip, event.ofp.buffer_id)
                print('> flow rule installation completed!')

            else:
                print('> installing flow rule: client -> server..')
                dest_server_ip = self.update_lb_mapping(src_ip)
                port_to_server = self.server_ips_info_table[str(dest_server_ip)]['port']
                self.install_flow_rule_client_to_server(connection, port_to_server, src_ip, dest_server_ip, event.ofp.buffer_id)
                print('> flow rule installation completed!')
        
        else:
            log.info("Unknown Packet type: %s" % packet.type)
            return
        return


# extra function to read json files
def load_json_dict(json_file):
    json_dict = {}    
    with open(json_file, 'r') as f:
        json_dict = json.load(f)
    return json_dict
    

# main launch routine
def launch(configuration_json_file):
    log.info("Loading Simple Load Balancer module")
    
    # load the configuration from file    
    configuration_dict = load_json_dict(configuration_json_file)   

    # the service IP that is publicly visible from the users' side   
    service_ip = IPAddr(configuration_dict['service_ip'])

    # the load balancer MAC with which the switch responds to ARP requests from users/servers
    lb_mac = EthAddr(configuration_dict['lb_mac'])

    # the IPs of the servers
    server_ips = [IPAddr(x) for x in configuration_dict['server_ips']]    

    # map users (IPs) to service groups (e.g., 10.0.0.5 to 'red')    
    user_ip_to_group = {}
    for user_ip,group in configuration_dict['user_groups'].items():
        user_ip_to_group[IPAddr(user_ip)] = group

    # map servers (IPs) to service groups (e.g., 10.0.0.1 to 'blue')
    server_ip_to_group = {}
    for server_ip,group in configuration_dict['server_groups'].items():
        server_ip_to_group[IPAddr(server_ip)] = group

    # do the launch with the given parameters
    core.registerNew(SimpleLoadBalancer, lb_mac, service_ip, server_ips, user_ip_to_group, server_ip_to_group)
    log.info("Simple Load Balancer module loaded")