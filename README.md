# BUREAU D'ETUDES
# sdn-pox-firewall
Implementation of stateful firewall using POX controller

# Instructions
## Download codes
```
mkdir sdn
cd sdn

git clone git://github.com/mininet/mininet
sudo mininet/util/install.sh -a
sudo mn -c
sudo mn --test pingall

sudo /usr/local/share/openvswitch/scripts/ovs-ctl start

git clone https://github.com/codes-libertes/sdn-pox-firewall.git

cp -rfpv sdn-pox-firewall/mn_firewall.py mininet/
cp -rfpv sdn-pox-firewall/firewall.config pox/
cp -rfpv sdn-pox-firewall/stateful_firewall_debug.py pox/
```
## Open a terminal for Mininet
```
cd mininet/
chmod 555 mn_firewall.py 
sudo mn -c
sudo ./mn_firewall.py 

mininet> xterm h1 h2 
mininet> sh ovs-vsctl show
mininet> sh ovs-ofctl dump-flows s1
mininet> sh ovs-ofctl del-flows s1
```
## Open a terminal for Pox
```
cd pox/
chmod 555 stateful_firewall_debug.py 
./pox.py stateful_firewall_debug --configuration=./firewall.config
```
## Test TCP 
```
h1> iperf -c 10.0.0.2 -p 5001 -t 100
h2> iperf -s -p 5001 -i 1
```
## Test UDP
```
h1> iperf -c 10.0.0.2 -u -t 100
h2> iperf -s -u -i 1
```
# Astuces
## How to kill a process
```
sudo ps -aux | grep pox
-----xxx  1.9  0.5 265612 20608 pts/2    Sl+  22:39   0:00 python2.7 -u ./pox.py fw --configuration=./firewall.config
sudo kill -9 xxx
```




