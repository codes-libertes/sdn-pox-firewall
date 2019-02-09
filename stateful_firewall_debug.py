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
		self.flow_table = {}
		self.inside_network = ["10.0.0.0/24"]
		self.config_openflow()
		"""
		add.Listeners= comme Ecouteur pour Appeler la fonction _handle_PacketIn.
		"""
		connection.addListeners(self)		
		 
	def config_openflow(self):
		"""
		All incoming packet flows to Controller
		"""
		self.config_protocol_flow(pkt.arp.REQUEST,pkt.ethernet.ARP_TYPE,None,None,None,None,True)
		self.config_protocol_flow(pkt.arp.REPLY,pkt.ethernet.ARP_TYPE,None,None,None,None,True)
		self.config_protocol_flow(pkt.ipv4.ICMP_PROTOCOL,pkt.ethernet.IP_TYPE,None,None,None,None,True)
		self.config_protocol_flow(pkt.ipv4.TCP_PROTOCOL,pkt.ethernet.IP_TYPE,None,None,None,None,True)

	def check_policy_TCP(self, nw_src, nw_dst, tp_dst=0):
		"""
		If all 3 parameters in l4_fw_rules, drop the packet; 
		"""	
		global l4_fw_rules	
		key = (str(nw_src),str(nw_dst),tp_dst)
		if key in l4_fw_rules:
			print "Policy from (%s) to (%s:%d) found" % (str(nw_src),str(nw_dst),tp_dst)
			return True
		else:
			print "No policy from (%s) to (%s:%d) found" % (str(nw_src),str(nw_dst),tp_dst)
			return False
			

	def check_policy_UDP(self):
		print ("[%s][%d][%s]" % (sys._getframe().f_code.co_filename,sys._getframe().f_lineno,sys._getframe().f_code.co_name))
	
	def check_policy_ARP(self,dl_src,dl_dst):
		print ("[%s][%d][%s]" % (sys._getframe().f_code.co_filename,sys._getframe().f_lineno,sys._getframe().f_code.co_name))
		"""
		If all 2 parameters in l2_fw_rules, drop the packet; 
		"""	
		global l2_fw_rules	
		key = (str(dl_src),str(dl_dst))
		print "key:",key
		if key in l2_fw_rules:
			print "Policy from (%s) to (%s:%d) found" % (str(dl_src),str(dl_dst))
			return True
		else:
			print "No policy from (%s) to (%s:%d) found" % (str(dl_src),str(dl_dst))
			return False

	def check_policy_ICMP(self):
		print ("[%s][%d][%s]" % (sys._getframe().f_code.co_filename,sys._getframe().f_lineno,sys._getframe().f_code.co_name))

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


	def act_like_firewall(self, packet, packet_in):
		"""
		pox/lib/packet/ethernet.py
		35020 :0x88cc:LLDP
		2048  :0x0800:IP
		34525 :0x86DD:IPv4
		"""
		if packet.type == packet.LLDP_TYPE:
			return
		
		if packet.type == packet.IPV6_TYPE:
			return
		
		print "Packet Type:", packet.type	
		#print packet_in

    		if packet.type == packet.ARP_TYPE:
			print "ARP Packet"
			tracker = ARPConnTrack(self,packet)
			if tracker:
				tracker.track_network()
		
		if packet.type == packet.IP_TYPE:
			ip_packet = packet.payload
			print "IP packet:", ip_packet.protocol
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

	"""
	la fonction _handle_PacketIn va traiter les donnees de OpenFlow [ARP, ICMP, TCP,UDP, ...]
	"""
	def _handle_PacketIn(self, event):
		print ("[%s][%d][%s]" % (sys._getframe().f_code.co_filename,sys._getframe().f_lineno,sys._getframe().f_code.co_name))
		packet = event.parsed
		if not packet.parsed:
			log.warning("Ignoring incomplete packets")
			return

		packet_in = event.ofp
		self.act_like_firewall(packet,packet_in)			
		
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
		decode = '{0:09b}'.format(tcp_packet.flags)
		#print "decode:",decode
		#print "seq:",tcp_packet.seq
		#print "ack:",tcp_packet.ack
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
		#print flags

	def track_network(self): 
        	"""
        	Tracks inside and outside network traffic
        	"""
		if self.fw.check_IPinside(self.pkt.payload.srcip):
			allow_resend = self.track_inside_network()
		else:
			allow_resend = self.track_outside_network()

		if True == allow_resend:
			self.fw.resend_packet(self.pkt)

	def track_inside_network(self): 
		print ("[%s][%d][%s]" % (sys._getframe().f_code.co_filename,sys._getframe().f_lineno,sys._getframe().f_code.co_name))
		ip_packet = self.pkt.payload	
		tcp_packet = ip_packet.payload
		key = (ip_packet.srcip,tcp_packet.srcport,ip_packet.dstip,tcp_packet.dstport)
	
		if True == self.fw.check_policy_TCP(ip_packet.srcip,ip_packet.dstip,tcp_packet.dstport):
			print "This packet matched the rule and dropped !!"
			return False

		return True 

		print "key:",key
		print "flow_table:",self.fw.flow_table
	
		if key in self.fw.flow_table:
			print "key in flow_table:",self.fw.flow_table
			if self.fw.flow_table[key][:2] == [1,"out"] and self.SYN and self.ACK:
				self.fw.flow_table[key][0] += 1
				self.fw.flow_table[key][1] = "in"
				print "TCP Packet SYN ACK from inside"
				return True
			elif self.fw.flow_table[key][:2] == [2,"out"] and self.ACK:
				self.fw.flow_table[key][0] += 1
				self.fw.flow_table[key][1] += "in"
				print "TCP Packet ACK from inside"
				return True
			elif self.fw.flow_table[key][2] < 100:
				self.fw.flow_table[key][2] += 1
				return True
			elif self.fw.flow_table[key][2] >= 100:
				del self.fw.flow_table[key][2]
				print "DOS attacks detected"
				return False
				
		else:
			#First TCP packet
			if self.SYN:
				print "self.SYN:",self.fw.flow_table
				#[Numbers of packets, Traffic direction,DOS]
				self.fw.flow_table[key] = [1,"in", 0]
				print "First TCP Packet SYN from inside"	
				return True	
	
	def track_outside_network(self): 
		print ("[%s][%d][%s]" % (sys._getframe().f_code.co_filename,sys._getframe().f_lineno,sys._getframe().f_code.co_name))
		ip_packet = self.pkt.payload	
		tcp_packet = ip_packet.payload
		key = (ip_packet.srcip,tcp_packet.srcport,ip_packet.dstip,tcp_packet.dstport)
		
		if True == self.fw.check_policy_TCP(ip_packet.srcip,ip_packet.dstip,tcp_packet.dstport):
			print "This packet matched the rule and dropped !!"
			return False

		return True

		print "key:",key
		print "flow_table:",self.fw.flow_table

		if key in self.fw.flow_table:
			print "key in flow_table:",self.fw.flow_table
			if self.fw.flow_table[key][:2] == [1,"in"] and self.SYN and self.ACK:
				self.fw.flow_table[key][0] += 1
				self.fw.flow_table[key][1] = "out"
				print "TCP Packet SYN ACK from outside"
				return True
			elif self.fw.flow_table[key][:2] == [2,"in"] and self.ACK:
				self.fw.flow_table[key][0] += 1
				self.fw.flow_table[key][1] += "out"
				print "TCP Packet ACK from outside"
				return True
			elif self.fw.flow_table[key][2] < 100: #It's a check to prevent from DOS
				self.fw.flow_table[key][2] += 1
				return True
			elif self.fw.flow_table[key][2] >= 100:
				del self.fw.flow_table[key][2]
				print "DOS attacks detected"
				return False
				
		else:
			#First TCP packet
			if self.SYN:
				print "self.SYN:",self.fw.flow_table
				#[Numbers of packets, Traffic direction,DOS]
				self.fw.flow_table[key] = [1,"out", 0]
				print "First TCP Packet SYN from outside"	
				return True	


class UDPConnTrack(object):

	def __init__(self,fw_obj,pkt):
		self.fw = fw_obj
		self.pkt = pkt
	
	def track_network(self): 
		print ("[%s][%d][%s]" % (sys._getframe().f_code.co_filename,sys._getframe().f_lineno,sys._getframe().f_code.co_name))


class ARPConnTrack(object):

	def __init__(self,fw_obj,pkt):
		self.fw = fw_obj
		self.pkt = pkt
	
	def track_network(self): 
		print ("[%s][%d][%s]" % (sys._getframe().f_code.co_filename,sys._getframe().f_lineno,sys._getframe().f_code.co_name))
		"""
		if True == check_policy_ARP(self,dl_src,dl_dst):
			print "This packet matched the rule and dropped !!"
			return False
		"""
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
	
def launch(config_l4="", config_l2=""):
	print "Starting Pox Firewall.."
	def start_firewall(event):
		Firewall(event.connection)

	parse_config_l4(config_l4)
	parse_config_l2(config_l2)
	core.openflow.addListenerByName("ConnectionUp",start_firewall)


"""
Global variables
@l4_fw_rules: <srcip>,<dstip>,<dstport>,<policy>
	   <srcip>:
	   <dstip>:
	   <dstport>:
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
dstport = 2
policy  = 3
l2_fw_rules  = {}
macsrc    = 0
macdst    = 1
macpolicy = 2
