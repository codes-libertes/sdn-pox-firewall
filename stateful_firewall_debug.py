import os
import sys
from pox.core import core
from netaddr import IPNetwork, IPAddress
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr

log = core.getLogger()
	
#print ("[%s][%d][%s]" % (sys._getframe().f_code.co_filename,sys._getframe().f_lineno,sys._getframe().f_code.co_name))

class Firewall(object):

	def __init__(self,connection):
		print ("[%s][%d][%s]" % (sys._getframe().f_code.co_filename,sys._getframe().f_lineno,sys._getframe().f_code.co_name))
  		"""
		self.connection = variable locale que on a enregistre connection (var externe)sur la var self.connection 
		"""
		self.connection = connection 
		self.flow_table = {}
		self.inside_network = ["10.0.0.0/24"]
		self.config_ARP_flow()
		self.config_ICMP_flow()
		self.config_TCP_flow()
		"""
		add.Listeners= comme Ecouteur pour Appeler la fonction _handle_PacketIn.
		"""
		connection.addListeners(self)		

	def config_ARP_flow(self):
		self.config_protocol_flow(pkt.arp.REQUEST,pkt.ethernet.ARP_TYPE,None,None,None,None,False)
		self.config_protocol_flow(pkt.arp.REPLY,pkt.ethernet.ARP_TYPE,None,None,None,None,False)
		
	def config_ICMP_flow(self):
		self.config_protocol_flow(pkt.ipv4.ICMP_PROTOCOL,pkt.ethernet.IP_TYPE,None,None,None,None,False)

	def config_TCP_flow(self):
		global config
		for rule in config:
			rule[srcip] = clean_ip(rule[srcip])	
			rule[dstip] = clean_ip(rule[dstip])	
			if rule[srcip] != 'any':
				nw_src = rule[srcip]
			else:	
				nw_src = None
			if rule[dstip] != 'any':
				nw_dst = rule[dstip]
			else:	
				nw_dst = None
			if rule[srcport] != 'any':
				tp_src = int(rule[srcport])
			else:	
				tp_src = None
			if rule[dstport] != 'any':
				tp_dst = int(rule[dstport])
			else:	
				tp_dst = None
			self.config_protocol_flow(pkt.ipv4.TCP_PROTOCOL,pkt.ethernet.IP_TYPE,nw_src,nw_dst,tp_src,tp_dst,True)

	def config_protocol_flow(self,nw_proto,dl_type,nw_src,nw_dst,tp_src,tp_dst,to_controller):
		"""
        	Configurations for ARP/ICMP/TCP/UDP packet flows
        	"""
		msg = of.ofp_flow_mod()
		match = of.ofp_match()
		match.nw_src = None
		match.nw_dst = None
		match.tp_src = None
		match.tp_dst = None
		match.nw_proto = nw_proto
		# 0x0800 for IPv4, 0x0806 for ARP
		match.dl_type = dl_type	
		msg.match = match
		msg.hard_timeout = 0
		msg.soft_timeout = 0
		msg.priority = 32768
		# TCP/UDP packets will be sent to Controller that decodes TCP flags
		if to_controller:
			action = of.ofp_action_output(port=of.OFPP_CONTROLLER)
		else:
			action = of.ofp_action_output(port=of.OFPP_NORMAL)

		msg.actions.append(action)
		self.connection.send(msg)

	def resend_packet(self,packet):
		ip_packet = packet.payload
		tcp_packet = ip_packet.payload

		fields = [str(ip_packet.srcip),str(tcp_packet.srcport),str(ip_packet.dstip),str(tcp_packet.dstport)]
                print fields
	
		self.config_protocol_flow(pkt.ipv4.TCP_PROTOCOL,pkt.ethernet.IP_TYPE,ip_packet.srcip,ip_packet.dstip,tcp_packet.srcport,tcp_packet.dstport,False)
		self.config_protocol_flow(pkt.ipv4.TCP_PROTOCOL,pkt.ethernet.IP_TYPE,ip_packet.dstip,ip_packet.srcip,tcp_packet.dstport,tcp_packet.srcport,False)
		
		msg = of.ofp_packet_out()
		msg.data = packet
		action = of.ofp_action_output(port=of.OFPP_NORMAL)
		msg.actions.append(action)
		self.connection.send(msg)


	def act_like_firewall(self,packet,packet_in):
		print ("[%s][%d][%s]" % (sys._getframe().f_code.co_filename,sys._getframe().f_lineno,sys._getframe().f_code.co_name))
		
		#pox/lib/packet/ethernet.py
		#35020:0x88cc:LLDP
		#2048 :0x0800:IP
		if packet.type == packet.LLDP_TYPE:
			return
		
		print "Packet Type:", packet.type	
		#print packet_in

		if packet.type == packet.IP_TYPE:
			ip_packet = packet.payload
			print "IP packet:", ip_packet.protocol
			#pox/lib/packet/ipv4.py
			#ICMP_PROTOCOL = 1:TCP_PROTOCOL  = 6:UDP_PROTOCOL  = 17
			if ip_packet.protocol == ip_packet.TCP_PROTOCOL:
				print "TCP Packet"
				tracker = TCPConnTrack(self,packet)
				if tracker:
					tracker.track_network()

			elif ip_packet.protocol == ip_packet.UDP_PROTOCOL:
				print "UDP Packet"
				tracker = UDPConnTrack(self,packet)
				if tracker:
					tracker.track_network()
			elif ip_packet.protocol == ip_packet.ICMP_PROTOCOL:
				print "ICMP Packet"

			self.resend_packet(packet)

	"""
	la fonction _handle_PacketIn va traiter les donnees de OpenFlow [ARP, ICMP, TCP,UDP, ...]
	"""
	def _handle_PacketIn(self,event):
		print ("[%s][%d][%s]" % (sys._getframe().f_code.co_filename,sys._getframe().f_lineno,sys._getframe().f_code.co_name))
		packet = event.parsed
		if not packet.parsed:
			log.warning("Ignoring incomplete packets")
			return

		packet_in = event.ofp
		self.act_like_firewall(packet,packet_in)			
		
	def check_IPinside(self,ip):
        	"""
        	Check if the IP is from inside the network or not.
        	"""
		print ("[%s][%d][%s]" % (sys._getframe().f_code.co_filename,sys._getframe().f_lineno,sys._getframe().f_code.co_name))
		for network in self.inside_network:
			if IPAddress(str(ip)) in IPNetwork(network):
				return True
		return False
	

class TCPConnTrack(object):

	def __init__(self,cap_obj,pkt):
		print ("[%s][%d][%s]" % (sys._getframe().f_code.co_filename,sys._getframe().f_lineno,sys._getframe().f_code.co_name))
		self.cap= cap_obj
		self.pkt = pkt
		self.set_flags()

	def set_flags(self):
		"""
        	Extracts and Sets the TCP flags (FIN, SYN, RST, PSH, ACK)
        	"""
		ip_packet = self.pkt.payload	
		tcp_packet = ip_packet.payload
		decode = '{0:09b}'.format(tcp_packet.flags)
		print "decode:",decode
		print "seq:",tcp_packet.seq
		print "ack:",tcp_packet.ack
		self.FIN = decode[-1]
		self.SYN = decode[-2]
		self.RST = decode[-3]
		self.PSH = decode[-4]
		self.ACK = decode[-5]
		self.URG = decode[-6]
		self.ECE = decode[-7]
		self.CWR = decode[-8]
		self.NS  = decode[-9]
	
		flags = [str(self.NS),str(self.CWR),str(self.ECE),str(self.URG),str(self.ACK),str(self.PSH),str(self.RST),str(self.SYN),str(self.FIN)]
		print flags

	def track_network(self): 
        	"""
        	Tracks inside and outside network traffic
        	"""
		if self.cap.check_IPinside(self.pkt.payload.srcip):
			self.track_inside_network()
		else:
			self.track_outside_network()

	def track_inside_network(self): 
		print ("[%s][%d][%s]" % (sys._getframe().f_code.co_filename,sys._getframe().f_lineno,sys._getframe().f_code.co_name))
		ip_packet = self.pkt.payload	
		tcp_packet = ip_packet.payload
		fields = [str(ip_packet.srcip),str(tcp_packet.srcport),str(ip_packet.dstip),str(tcp_packet.dstport)]
		print fields
		key = (ip_packet.srcip,tcp_packet.srcport,ip_packet.dstip,tcp_packet.dstport)
		
		print "key:",key
		print "flow_table:",self.cap.flow_table
	
		if key in self.cap.flow_table:
			print "key in flow_table:",self.cap.flow_table
			if self.cap.flow_table[key][:2] == [1,"out"] and self.SYN and self.ACK:
				self.cap.flow_table[key][0] += 1
				self.cap.flow_table[key][1] = "in"
				print "TCP Packet SYN ACK from inside"
				return True
			elif self.cap.flow_table[key][:2] == [2,"out"] and self.ACK:
				self.cap.flow_table[key][0] += 1
				self.cap.flow_table[key][1] += "in"
				print "TCP Packet ACK from inside"
				return True
			elif self.cap.flow_table[key][2] < 100: #It's a check to prevent from DOS
				self.cap.flow_table[key][2] += 1
				return True
			elif self.cap.flow_table[key][2] >= 100:
				del self.cap.flow_table[key][2]
				print "DOS attacks detected"
				return False
				
		else:
			#First TCP packet
			if self.SYN:
				print "self.SYN:",self.cap.flow_table
				#[Numbers of packets, Traffic direction,DOS]
				self.cap.flow_table[key] = [1,"in", 0]
				print "First TCP Packet SYN from inside"	
				return True	
	
	def track_outside_network(self): 
		print ("[%s][%d][%s]" % (sys._getframe().f_code.co_filename,sys._getframe().f_lineno,sys._getframe().f_code.co_name))
		ip_packet = self.pkt.payload	
		tcp_packet = ip_packet.payload
		#fields = [str(ip_packet.srcip),str(tcp_packet.srcport),str(ip_packet.dstip),str(tcp_packet.dstport)]
		#print fields
		key = (ip_packet.srcip,tcp_packet.srcport,ip_packet.dstip,tcp_packet.dstport)

		print "key:",key
		print "flow_table:",self.cap.flow_table

		if key in self.cap.flow_table:
			print "key in flow_table:",self.cap.flow_table
			if self.cap.flow_table[key][:2] == [1,"in"] and self.SYN and self.ACK:
				self.cap.flow_table[key][0] += 1
				self.cap.flow_table[key][1] = "out"
				print "TCP Packet SYN ACK from outside"
				return True
			elif self.cap.flow_table[key][:2] == [2,"in"] and self.ACK:
				self.cap.flow_table[key][0] += 1
				self.cap.flow_table[key][1] += "out"
				print "TCP Packet ACK from outside"
				return True
			elif self.cap.flow_table[key][2] < 100: #It's a check to prevent from DOS
				self.cap.flow_table[key][2] += 1
				return True
			elif self.cap.flow_table[key][2] >= 100:
				del self.cap.flow_table[key][2]
				print "DOS attacks detected"
				return False
				
		else:
			#First TCP packet
			if self.SYN:
				print "self.SYN:",self.cap.flow_table
				#[Numbers of packets, Traffic direction,DOS]
				self.cap.flow_table[key] = [1,"out", 0]
				print "First TCP Packet SYN from outside"	
				return True	


class UDPConnTrack(object):

	def __init__(self,cap_obj,pkt):
		print ("[%s][%d][%s]" % (sys._getframe().f_code.co_filename,sys._getframe().f_lineno,sys._getframe().f_code.co_name))
		self.cap = cap_obj
		self.pkt = pkt
	
	def track_network(self): 
		print ("[%s][%d][%s]" % (sys._getframe().f_code.co_filename,sys._getframe().f_lineno,sys._getframe().f_code.co_name))

def clean_ip(cidrAddress):
	strAddress = cidrAddress.split('/',2)
	if len(strAddress) == 1:
		return cidrAddress
	uintAddress = IPAddr(strAddress[0]).toUnsigned()
	hostMask = 32-int(strAddress[1])
	hostAddress = uintAddress & ((1<<hostMask) -1 )
	print "uintAddress:",uintAddress
	print "hostMask:",hostMask
	print "hostAddress:",hostAddress
	if (hostAddress == 0):
		return cidrAddress
	else:
		return strAddress[0]

def parse_config(configuration):
	print ("[%s][%d][%s]" % (sys._getframe().f_code.co_filename,sys._getframe().f_lineno,sys._getframe().f_code.co_name))
	"""
 	<srcip> [ / <netmask> ] <srcport> <dstip> [ / <netmask> ] <dstport>
	"""
	global config	
	fin = open(configuration)
	for line in fin:
		rule = line.split()
		print "rule:",rule
		if (len(rule) > 0):
			config.append(rule)

def parse_configmac(config_mac):
	print ("[%s][%d][%s]" % (sys._getframe().f_code.co_filename,sys._getframe().f_lineno,sys._getframe().f_code.co_name))
	"""
 	<srcip> [ / <netmask> ] <srcport> <dstip> [ / <netmask> ] <dstport>
	"""
	"""
	lire le fichier firewall-config-mac
	"""
	
	global configmac	
	fin = open(config_mac)
        """
	split pour copier le 1er ligne des @ mac en deux partie macsrc mac dst 00:00:00:00:00:01(partie1)/00:00:00:00:00:02(par2)
	"""
	for line in fin:
		macrule = line.split()
		print "MAC rule:",macrule
		if (len(macrule) > 0):
			configmac.append(macrule)	
	
def launch(configuration="", config_mac=""):

	print "Starting Pox Firewall.."
	def start_firewall(event):
		print ("[%s][%d][%s]" % (sys._getframe().f_code.co_filename,sys._getframe().f_lineno,sys._getframe().f_code.co_name))
		Firewall(event.connection)

	parse_config(configuration)
	parse_configmac(config_mac)
	"""
	core pour connecter au pare-feu via la fonction en haut (firewall (eveent.connection)) et appliquer la class en haut class firewall (object)
	"""
	core.openflow.addListenerByName("ConnectionUp",start_firewall)
"""
Global variables
"""
config  = []
srcip   = 0
srcport = 1
dstip   = 2
dstport = 3
configmac  = []
macsrc   = 0
macdst = 1


