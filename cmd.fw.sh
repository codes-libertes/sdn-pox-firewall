
#sites
https://github.com/raonadeem/Pyretic-statefull-firewall
https://github.com/frenetic-lang/pyretic.git
https://github.com/frenetic-lang/frenetic
http://csie.nqu.edu.tw/smallko/sdn/pyretic_and_pox.htm

https://github.com/rohan47/pox_firewall/blob/master/firewall.py
https://github.com/raonadeem/Pyretic-statefull-firewall/blob/master/statefull_firewall.py
https://github.com/matt-welch/POX_Firewall/blob/master/Firewall.py

https://pentest.blog/how-to-perform-ddos-test-as-a-pentester/

=====================================================================================
${CURRENT_DIR}=

sudo /usr/local/share/openvswitch/scripts/ovs-ctl start

nc -k -l 9000
curl http://localhost:9000
netstat -nlp | grep 9000
telnet localhost 9000
nmap localhost

#0.Mininet
git clone git://github.com/mininet/mininet
sudo mininet/util/install.sh -a
sudo mn --test pingall

sudo apt-get install python-dev python-pip python-setuptools
sudo pip install .
sudo pip install webob
sudo pip install eventlet
sudo pip install paramiko
sudo pip install routes


#1.Clone the firewall codes
git clone https://github.com/raonadeem/Pyretic-statefull-firewall.git

#2.Clone the pyretic codes
git clone https://github.com/frenetic-lang/pyretic.git

#3.Replace files
mv Pyretic-statefull-firewall/firewall-policies.csv pyretic/
mv Pyretic-statefull-firewall/statefull_firewall.py pyretic/pyretic/examples/


=====================================================================================
#1.Clean mininet setup at the beginning
sudo mn -c

#2.Setup 3 hosts (h1,h2,h3) on the single switch s1 and a remote controller
sudo mn --topo single,3 --controller remote

#3.Open xterm for h1 ,h2 ,h3
xterm h1
xterm h2
xterm h3

#4.On h1, run the hping3 tests
sudo apt-get install hping3
#wget https://inmon.com/products/sFlow-RT/sflow-rt.tar.gz
sudo hping3 -V -S -s 6001 -p 5001 10.0.0.3 -c 1

#5.On h3, run statefull firewall application on POX controller
sudo apt-get install -y python-ipaddr
sudo apt-get install -y python-bitarray
sudo apt-get install -y python-networkx
pip install yappi
pip install pydot
pip install pyparsing
pip install frenetic
export PYTHONPATH=${CURRENT_PATH}/pyretic:${CURRENT_PATH}/pox/${CURRENT_PATH}/mininet
eval `opam config env`
python pyretic.py pyretic.examples.statefull_firewall

=====================================================================================
export PYTHONPATH=~/sdn/pox:~/sdn/pyretic
./pyretic.py -m p0 pyretic.tutorial.myroute_dijkstra

./pox.py pox.openflow.of_01 --port=5566 with_pyretic pox.openflow.discovery pox.forwarding.l3_learning

sudo ./test_multicontroller.py

#h1 
iperf -c 10.0.0.2 -u -t 100
#h2
iperf -s -u -i 1

