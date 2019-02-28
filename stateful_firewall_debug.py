import os
import sys
from pox.core import core
from netaddr import IPNetwork, IPAddress
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr
import re

log = core.getLogger()
	
#print ("[%s][%d][%s]" % (sys._getframe().f_code.co_filename,sys._getframe().f_lineno,sys._getframe().f_code.co_name))

class Firewall(object):

	def __init__(self, connection):
  		"""
		self.connection = variable locale que on a enregistre connection (var externe)sur la var self.connection 
		"""
		self.connection = connection 
		self.ip_seq_table = {}
		self.ip_port_table = {}
		self.actve_connection_table = {}
		self.inside_network = ["10.0.0.0/24"]
		self.verify_legitimite()
		"""
		add.Listeners= comme Ecouteur pour Appeler la fonction _handle_PacketIn.
		"""
		connection.addListeners(self)		
	
	def verify_legitimite(self):
		"""
		Allow all legal incoming packet flows to Controller
		"""
		"""
		print ("[%s][%d][%s]" % (sys._getframe().f_code.co_filename,sys._getframe().f_lineno,sys._getframe().f_code.co_name))
		global l4_fw_rules	
		for key in l4_fw_rules:
			print "srcip:",l4_fw_rules[key][srcip]
			print "dstip:",l4_fw_rules[key][dstip]
		"""
		self.config_protocol_flow(pkt.arp.REQUEST,pkt.ethernet.ARP_TYPE,None,None,None,None,True)
		self.config_protocol_flow(pkt.arp.REPLY,pkt.ethernet.ARP_TYPE,None,None,None,None,True)
		self.config_protocol_flow(pkt.ipv4.ICMP_PROTOCOL,pkt.ethernet.IP_TYPE,None,None,None,None,True)
		self.config_protocol_flow(pkt.ipv4.TCP_PROTOCOL,pkt.ethernet.IP_TYPE,None,None,None,None,True)
	
	def check_policy_l3(self, nw_src, nw_dst):
		"""
		If all 2 parameters in l3_fw_rules, drop the packet; 
		"""	
		global l3_fw_rules	
		key = (str(nw_src),str(nw_dst))
		if key in l3_fw_rules:
			print "L3 firewall check: Policy from (%s) to (%s) found" % (str(nw_src),str(nw_dst))
			return True
		else:
			print "L3 firewall check: No policy from (%s) to (%s) found" % (str(nw_src),str(nw_dst))
			return False
	
	def update_policy_l3(self, nw_src, nw_dst):
		"""
		Update all 2 parameters in l3_fw_rules; 
		"""	
		global l3_fw_rules	
		key = (str(nw_src),str(nw_dst))
		if key in l3_fw_rules:
			print "L3 firewall update: Policy from (%s) to (%s) found" % (str(nw_src),str(nw_dst))
		else:
			l3_fw_rules[key] = True
			print "L3 firewall update: Add policy from (%s) to (%s) found" % (str(nw_src),str(nw_dst))

	def check_policy_l4(self, nw_src, nw_dst, tp_dst=0):
		"""
		If all 3 parameters in l4_fw_rules, drop the packet; 
		"""	
		global l4_fw_rules	
		key = (str(nw_src),str(nw_dst),tp_dst)
		if key in l4_fw_rules:
			print "L4 firewall check: Policy from (%s) to (%s:%d) found" % (str(nw_src),str(nw_dst),tp_dst)
			return True
		else:
			print "L4 firewall check: No policy from (%s) to (%s:%d) found" % (str(nw_src),str(nw_dst),tp_dst)
			return False
	
	def check_policy_l2(self,dl_src,dl_dst):
		print ("[%s][%d][%s]" % (sys._getframe().f_code.co_filename,sys._getframe().f_lineno,sys._getframe().f_code.co_name))
		"""
		If all 2 parameters in l2_fw_rules, drop the packet; 
		"""	
		global l2_fw_rules	
		key = (str(dl_src), str(dl_dst))
		print "key:",key
		if key in l2_fw_rules:
			print "L2 firewall check: Policy from (%s) to (%s) found" % (str(dl_src), str(dl_dst))
			return True
		else:
			print "L2 firewall check: No policy from (%s) to (%s) found" % (str(dl_src), str(dl_dst))
			return False

	def config_protocol_flow(self, nw_proto, dl_type, nw_src, nw_dst, tp_src, tp_dst, to_controller):
		"""
        	Configurations for ARP/ICMP/TCP/UDP packet flows
        	"""
		msg = of.ofp_flow_mod()
		match = of.ofp_match()

		match.nw_src = nw_src
		match.nw_dst = nw_dst
		match.tp_src = tp_src
		match.tp_dst = tp_dst

		match.nw_proto = nw_proto
		# 0x0800 for IPv4, 0x0806 for ARP
		match.dl_type = dl_type	
		msg.match = match
		msg.hard_timeout = 0
		msg.soft_timeout = 0
		msg.priority = 32768
		"""
		@ARGS:
			True: directly go up to Controller
			False:directly bypass controller and forward packets
		"""
		if to_controller:
			action = of.ofp_action_output(port=of.OFPP_CONTROLLER)
		else:
			action = of.ofp_action_output(port=of.OFPP_NORMAL)

		msg.actions.append(action)
		self.connection.send(msg)

	def resend_packet(self, packet):
		ip_packet = packet.payload
		tcp_packet = ip_packet.payload
					   
                self.config_protocol_flow(pkt.ipv4.TCP_PROTOCOL,pkt.ethernet.IP_TYPE,ip_packet.srcip,ip_packet.dstip,tcp_packet.srcport,tcp_packet.dstport,False)
                self.config_protocol_flow(pkt.ipv4.TCP_PROTOCOL,pkt.ethernet.IP_TYPE,ip_packet.dstip,ip_packet.srcip,tcp_packet.dstport,tcp_packet.srcport,False)
		msg = of.ofp_packet_out()
		msg.data = packet
		action = of.ofp_action_output(port=of.OFPP_NORMAL)
		msg.actions.append(action)
		self.connection.send(msg)


	def _handle_PacketIn(self, event):
		packet = event.parsed
		if not packet.parsed:
			log.warning("Ignoring incomplete packets")
			return

		"""
		pox/lib/packet/ethernet.py
		35020 :0x88cc:LLDP
		2048  :0x0800:IP
		34525 :0x86DD:IPv4
		"""
		print "Packet Type:", packet.type	
		if packet.type == packet.LLDP_TYPE:
			return
		
		if packet.type == packet.IPV6_TYPE:
			return
		
    		if packet.type == packet.ARP_TYPE:
			print "ARP Packet"
			print "event.port:",event.port
			tracker = ARPConnTrack(self,packet)
			if tracker:
				tracker.track_network()
		
		if packet.type == packet.IP_TYPE:
			ip_packet = packet.payload
			"""
			pox/lib/packet/ipv4.py
			ICMP_PROTOCOL = 1
			TCP_PROTOCOL  = 6
			UDP_PROTOCOL  = 17
			"""
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
				tracker = ICMPConnTrack(self,packet)
				if tracker:
					tracker.track_network()
		
	def check_IPinside(self, ip):
        	"""
        	Check if the IP is from inside the network or not.
        	"""
		for network in self.inside_network:
			if IPAddress(str(ip)) in IPNetwork(network):
				return True
		return False
	

class TCPConnTrack(object):

	def __init__(self,fw_obj,pkt):
		self.fw= fw_obj
		self.pkt = pkt
		self.set_flags()

	def set_flags(self):
		"""
        	Extracts and Sets the TCP flags (FIN, SYN, RST, PSH, ACK)
        	"""
		ip_packet = self.pkt.payload	
		tcp_packet = ip_packet.payload
		"""
		INFO:packet:Truncated TCP option; incomplete packet
		"""
		if tcp_packet is None:
			return
	
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

	def track_network(self): 
        	"""
        	Tracks inside and outside network traffic
        	"""
		if self.fw.check_IPinside(self.pkt.payload.srcip):
			self.track_inside_network()
		else:
			self.track_outside_network()

		self.fw.resend_packet(self.pkt)

	def track_inside_network(self): 
		ip_packet = self.pkt.payload	
		tcp_packet = ip_packet.payload
	
		key = (str(ip_packet.srcip),str(tcp_packet.srcport),str(ip_packet.dstip),str(tcp_packet.dstport))

		if key in self.fw.ip_port_table:
			if self.fw.ip_port_table[key][:2] == [1,"out"] and self.SYN and self.ACK:
				self.fw.ip_port_table[key][0] +=1
				self.fw.ip_port_table[key][1] = "in"
				print "TCP SYN-ACK from inside"
				return True		
			elif self.fw.ip_port_table[key][:2] == [2,"out"] and self.ACK:
				del self.fw.ip_port_table[key]
				self.fw.ip_seq_table[key] = [int(tcp_packet.seq)]
				self.fw.actve_connection_table[key] = ["active"]
				print "self.fw.actve_connection_table:",self.fw.actve_connection_table
				print "TCP ACK from inside"
				return True		
		else:
			"""
			Establishment of TCP connection	
			"""
			if self.SYN:
				"""
				[Order of packets, traffic direction]
				"""
				self.fw.ip_port_table[key] = [1,"in"]
				print "TCP SYN from inside"
				return True

	
	def track_outside_network(self): 
		ip_packet = self.pkt.payload	
		tcp_packet = ip_packet.payload
	
		key = (str(ip_packet.dstip),str(tcp_packet.dstport),str(ip_packet.srcip),str(tcp_packet.srcport))

		if key in self.fw.ip_port_table:
			if self.fw.ip_port_table[key][:2] == [1,"in"] and self.SYN and self.ACK:
				self.fw.ip_port_table[key][0] +=1
				self.fw.ip_port_table[key][1] = "out"
				print "TCP SYN-ACK from outside"
				return True		
			elif self.fw.ip_port_table[key][:2] == [2,"in"] and self.ACK:
				del self.fw.ip_port_table[key]
				keyinverse = (str(ip_packet.srcip),str(tcp_packet.srcport),str(ip_packet.dstip),str(tcp_packet.dstport))
				self.fw.ip_seq_table[keyinverse] = [int(tcp_packet.seq)]
				self.fw.actve_connection_table[keyinverse] = ["active"]
				print "self.fw.actve_connection_table:",self.fw.actve_connection_table
				print "TCP ACK from outside"
				return True		
		else:
			"""
			Establishment of TCP connection	
			"""
			if self.SYN:
				"""
				[Order of packets, traffic direction]
				"""
				self.fw.ip_port_table[key] = [1,"out"]
				print "TCP SYN from outside"
				return True


class UDPConnTrack(object):

	def __init__(self,fw_obj,pkt):
		self.fw = fw_obj
		self.pkt = pkt
	
	def track_network(self): 
		print ("[%s][%d][%s]" % (sys._getframe().f_code.co_filename,sys._getframe().f_lineno,sys._getframe().f_code.co_name))


class ICMPConnTrack(object):

	def __init__(self,fw_obj,pkt):
		self.fw = fw_obj
		self.pkt = pkt
	
	def track_network(self):
		self.fw.config_protocol_flow(pkt.ipv4.ICMP_PROTOCOL,pkt.ethernet.IP_TYPE,None,None,None,None,False)

class ARPConnTrack(object):

	def __init__(self,fw_obj,pkt):
		self.fw = fw_obj
		self.pkt = pkt
	
	def config_flow(self, nw_proto, dl_type, dl_src, dl_dst):
		"""
        	Configurations for ARPpacket flows
        	"""
		msg = of.ofp_flow_mod()
		match = of.ofp_match()
		match.dl_src = dl_src
		match.dl_dst = dl_dst
		match.nw_proto = nw_proto
		match.dl_type = dl_type	
		msg.match = match
		msg.priority = 32768
		
		if str(dl_dst) == "ff:ff:ff:ff:ff:ff":
			action = of.ofp_action_output(port=of.OFPP_FLOOD)
		else:
			action = of.ofp_action_output(port=of.OFPP_NORMAL)
		msg.actions.append(action)
		self.fw.connection.send(msg)
	
	def track_network(self): 
		print ("[%s][%d][%s]" % (sys._getframe().f_code.co_filename,sys._getframe().f_lineno,sys._getframe().f_code.co_name))

		self.fw.config_protocol_flow(pkt.arp.REQUEST,pkt.ethernet.ARP_TYPE,None,None,None,None,False)
		self.fw.config_protocol_flow(pkt.arp.REPLY,pkt.ethernet.ARP_TYPE,None,None,None,None,False)


def clean_ip(cidrAddress):
	strAddress = cidrAddress.split('/',2)
	if len(strAddress) == 1:
		return cidrAddress
	uintAddress = IPAddr(strAddress[0]).toUnsigned()
	hostMask = 32-int(strAddress[1])
	hostAddress = uintAddress & ((1<<hostMask) -1 )
	#print "uintAddress:",uintAddress
	#print "hostMask:",hostMask
	#print "hostAddress:",hostAddress
	if (hostAddress == 0):
		return cidrAddress
	else:
		return strAddress[0]

def str_bool(policy):
	"""
	policy: many options 
	"""
	if str(policy).lower() in ("yes","y","true","t","allow","permit","1"):
		return False
	if str(policy).lower() in ("no","n","false","f","block","deny","0"):
		return True

def parse_config_l4(config_l4):
	global l4_fw_rules	
	fin = open(config_l4)
	for line in fin:
		rule = re.sub(r'\s', '',line).split(',')
		print "ip rule:",rule
		if (len(rule) > 0):
			nw_src = clean_ip(rule[srcip])	
			nw_dst = clean_ip(rule[dstip])	
			tp_dst = int(rule[dstport])
			key = (nw_src,nw_dst,tp_dst)
			if True == str_bool(rule[policy]):
				l4_fw_rules[key] = True	

def parse_config_l3(config_l3):
	global l3_fw_rules	
	fin = open(config_l3)
	for line in fin:
		rule = re.sub(r'\s', '',line).split(',')
		print "ip rule:",rule
		if (len(rule) > 0):
			nw_src = clean_ip(rule[srcip])	
			nw_dst = clean_ip(rule[dstip])	
			key = (nw_src,nw_dst)
			if True == str_bool(rule[policy]):
				l3_fw_rules[key] = True	

def parse_config_l2(config_l2):
	global l2_fw_rules	
	fin = open(config_l2)
	for line in fin:
		rule = re.sub(r'\s', '',line).split(',')
		print "mac rule:",rule
		if (len(rule) > 0):
			dl_src = rule[macsrc]
			dl_dst = rule[macdst]	
			key = (dl_src,dl_dst)
			if True == str_bool(rule[macpolicy]):
				l2_fw_rules[key] = True	
	
def launch(config_l4="", config_l2="", config_l3=""):
	print "Starting Pox Firewall.."
	def start_firewall(event):
		Firewall(event.connection)

	if config_l4 != "":
		parse_config_l4(config_l4)

	if config_l3 != "":
		parse_config_l3(config_l3)

	if config_l2 != "":
		parse_config_l2(config_l2)

	core.openflow.addListenerByName("ConnectionUp",start_firewall)


"""
Global variables
@l4_fw_rules: <srcip>,<dstip>,<policy>,<dstport>
	   <srcip>:
	   <dstip>:
	   <policy>:
		-"yes","y","true","t","allow","permit","1"
		-"no","n","false","f","block","deny","0"
	   <dstport>:
@l3_fw_rules: <srcip>,<dstip>,<policy>
	   <srcip>:
	   <dstip>:
	   <policy>:
		-"yes","y","true","t","allow","permit","1"
		-"no","n","false","f","block","deny","0"
@l2_fw_rules: <macsrc>,<macdst>,<policy>
	   <macsrc>:
	   <macdst>:
	   <policy>:
		-"yes","y","true","t","allow","permit","1"
		-"no","n","false","f","block","deny","0"
"""
l4_fw_rules  = {}
srcip   = 0
dstip   = 1
policy  = 2
dstport = 3
l3_fw_rules  = {}
l2_fw_rules  = {}
macsrc    = 0
macdst    = 1
macpolicy = 2
