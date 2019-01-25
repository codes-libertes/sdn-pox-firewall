# sdn-pox-firewall
Implementation of stateful firewall using POX controller

# Instructions
mkdir sdn
cd sdn/

git clone git://github.com/mininet/mininet
sudo mininet/util/install.sh -a
sudo mn -c
sudo mn --test pingall

sudo /usr/local/share/openvswitch/scripts/ovs-ctl start

sudo mn --topo single,2 --mac --switch ovsk --controller remote
mininet> xterm h1 h2 
mininet> sh ovs-vsctl show
mininet> sh ovs-ofctl dump-flows s1

--TCP
h1> iperf -c 10.0.0.2 -p 5001 -t 100
h2> iperf -s -p 5001 -i 1

--UDP 
h1> iperf -c 10.0.0.2 -u -t 100
h2> iperf -s -u -i 1





