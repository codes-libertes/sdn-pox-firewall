
#website
https://stackoverflow.com/questions/37998065/understanding-ryu-openflow-controller-mininet-wireshark-and-tcpdump
https://ervikrant06.wordpress.com/2015/09/18/learning-ovs-open-vswitch-using-mininet-part-4/
http://csie.nqu.edu.tw/smallko/sdn/iperf_mininet.htm
https://media.readthedocs.org/pdf/ovs-istokes/dpdk_merge_2_9/ovs-istokes.pdf

#terminologies
dl:data link
nw:network
tp:transport

# mininet
git clone git://github.com/mininet/mininet
sudo mininet/util/install.sh -a
sudo mn --test pingall

#ryu
git clone git://github.com/osrg/ryu.git
cd ryu/
sudo apt-get install python-dev python-pip python-setuptools
sudo pip install .
sudo pip install webob
sudo pip install eventlet
sudo pip install paramiko
sudo pip install routes


#mininet+ryu
cd ../
sudo mn --topo single,3 --mac --switch ovsk --controller remote
xterm h1 h2 h3

tcpdump -XX -n -i h2-eth0  
tcpdump -XX -n -i h3-eth0

#ryu 
cd ryu/
sudo PYTHONPATH=. ./bin/ryu-manager ryu/app/simple_switch_13.py


#open vSwitch
sudo ovs-vsctl show
sudo ovs-ofctl dump-flows s1

#mininet accesses ovs
sudo mn 
mininet>sh ovs-vsctl show
mininet>h1 ifconfig
mininet>h2 ifconfig
mininet>sh ovs-ofctl del-flows s1
mininet>sh ovs-ofctl dump-flows s1

#ARP
 cookie=0x0, duration=14.547s, table=0, n_packets=2, n_bytes=84, idle_timeout=60, idle_age=14, priority=65535,arp,in_port=2,vlan_tci=0x0000,dl_src=de:2e:fe:ad:0c:79,dl_dst=9e:8b:7c:02:19:9b,arp_spa=10.0.0.2,arp_tpa=10.0.0.1,arp_op=1 actions=output:1
 cookie=0x0, duration=14.546s, table=0, n_packets=2, n_bytes=84, idle_timeout=60, idle_age=14, priority=65535,arp,in_port=1,vlan_tci=0x0000,dl_src=9e:8b:7c:02:19:9b,dl_dst=de:2e:fe:ad:0c:79,arp_spa=10.0.0.1,arp_tpa=10.0.0.2,arp_op=1 actions=output:2
 cookie=0x0, duration=14.545s, table=0, n_packets=1, n_bytes=42, idle_timeout=60, idle_age=14, priority=65535,arp,in_port=1,vlan_tci=0x0000,dl_src=9e:8b:7c:02:19:9b,dl_dst=de:2e:fe:ad:0c:79,arp_spa=10.0.0.1,arp_tpa=10.0.0.2,arp_op=2 actions=output:2
 cookie=0x0, duration=14.545s, table=0, n_packets=1, n_bytes=42, idle_timeout=60, idle_age=14, priority=65535,arp,in_port=2,vlan_tci=0x0000,dl_src=de:2e:fe:ad:0c:79,dl_dst=9e:8b:7c:02:19:9b,arp_spa=10.0.0.2,arp_tpa=10.0.0.1,arp_op=2 actions=output:1

#ICMP
 cookie=0x0, duration=20.511s, table=0, n_packets=1, n_bytes=98, idle_timeout=60, idle_age=20, priority=65535,icmp,in_port=1,vlan_tci=0x0000,dl_src=9e:8b:7c:02:19:9b,dl_dst=de:2e:fe:ad:0c:79,nw_src=10.0.0.1,nw_dst=10.0.0.2,nw_tos=0,icmp_type=8,icmp_code=0 actions=output:2
 cookie=0x0, duration=20.508s, table=0, n_packets=1, n_bytes=98, idle_timeout=60, idle_age=20, priority=65535,icmp,in_port=2,vlan_tci=0x0000,dl_src=de:2e:fe:ad:0c:79,dl_dst=9e:8b:7c:02:19:9b,nw_src=10.0.0.2,nw_dst=10.0.0.1,nw_tos=0,icmp_type=0,icmp_code=0 actions=output:1

#net
mininet>net


#TCP
mininet>xterm h1 h2
#h2
iperf -s -p 5566 -i 1
#h1
iperf -c 10.0.0.2 -p 5566 -t 15

#TCP s-c h2->h1
 cookie=0x0, duration=31.825s, table=0, n_packets=524262, n_bytes=34659792, idle_timeout=60, idle_age=16, priority=65535,tcp,in_port=2,vlan_tci=0x0000,dl_src=de:2e:fe:ad:0c:79,dl_dst=9e:8b:7c:02:19:9b,nw_src=10.0.0.2,nw_dst=10.0.0.1,nw_tos=0,tp_src=5566,tp_dst=34188 actions=output:1
 cookie=0x0, duration=31.822s, table=0, n_packets=899479, n_bytes=45442858950, idle_timeout=60, idle_age=16, priority=65535,tcp,in_port=1,vlan_tci=0x0000,dl_src=9e:8b:7c:02:19:9b,dl_dst=de:2e:fe:ad:0c:79,nw_src=10.0.0.1,nw_dst=10.0.0.2,nw_tos=0,tp_src=34188,tp_dst=5566 actions=output:2
 cookie=0x0, duration=26.736s, table=0, n_packets=1, n_bytes=42, idle_timeout=60, idle_age=26, priority=65535,arp,in_port=2,vlan_tci=0x0000,dl_src=de:2e:fe:ad:0c:79,dl_dst=9e:8b:7c:02:19:9b,arp_spa=10.0.0.2,arp_tpa=10.0.0.1,arp_op=1 actions=output:1
 cookie=0x0, duration=26.734s, table=0, n_packets=1, n_bytes=42, idle_timeout=60, idle_age=26, priority=65535,arp,in_port=1,vlan_tci=0x0000,dl_src=9e:8b:7c:02:19:9b,dl_dst=de:2e:fe:ad:0c:79,arp_spa=10.0.0.1,arp_tpa=10.0.0.2,arp_op=2 actions=output:2

#TCP s-c h1->h2
 cookie=0x0, duration=23.915s, table=0, n_packets=580979, n_bytes=38345234, idle_timeout=60, idle_age=8, priority=65535,tcp,in_port=1,vlan_tci=0x0000,dl_src=9e:8b:7c:02:19:9b,dl_dst=de:2e:fe:ad:0c:79,nw_src=10.0.0.1,nw_dst=10.0.0.2,nw_tos=0,tp_src=5566,tp_dst=47212 actions=output:2
 cookie=0x0, duration=23.913s, table=0, n_packets=907821, n_bytes=44230121746, idle_timeout=60, idle_age=8, priority=65535,tcp,in_port=2,vlan_tci=0x0000,dl_src=de:2e:fe:ad:0c:79,dl_dst=9e:8b:7c:02:19:9b,nw_src=10.0.0.2,nw_dst=10.0.0.1,nw_tos=0,tp_src=47212,tp_dst=5566 actions=output:1
 cookie=0x0, duration=18.766s, table=0, n_packets=1, n_bytes=42, idle_timeout=60, idle_age=18, priority=65535,arp,in_port=1,vlan_tci=0x0000,dl_src=9e:8b:7c:02:19:9b,dl_dst=de:2e:fe:ad:0c:79,arp_spa=10.0.0.1,arp_tpa=10.0.0.2,arp_op=1 actions=output:2
 cookie=0x0, duration=18.764s, table=0, n_packets=1, n_bytes=42, idle_timeout=60, idle_age=18, priority=65535,arp,in_port=2,vlan_tci=0x0000,dl_src=de:2e:fe:ad:0c:79,dl_dst=9e:8b:7c:02:19:9b,arp_spa=10.0.0.2,arp_tpa=10.0.0.1,arp_op=2 actions=output:1








