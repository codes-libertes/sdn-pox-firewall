import os
import sys
from pox.core import core
from netaddr import IPNetwork, IPAddress

log = core.getLogger()
	
#print ("[%s][%d][%s]" % (sys._getframe().f_code.co_filename,sys._getframe().f_lineno,sys._getframe().f_code.co_name))

class Firewall(object):

	def __init__(self,connection):
		print ("[%s][%d][%s]" % (sys._getframe().f_code.co_filename,sys._getframe().f_lineno,sys._getframe().f_code.co_name))
		self.connection = connection
		self.flow_table = {}
		self.inside_network = ["10.0.0.0/24"]
		connection.addListeners(self)

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

def launch():
	print "Starting Pox Firewall.."
	def start_firewall(event):
		Firewall(event.connection)
	
	core.openflow.addListenerByName("ConnectionUp",start_firewall)

