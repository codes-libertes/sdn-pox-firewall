#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch, UserSwitch
from mininet.cli import CLI
from mininet.link import Link, TCLink

def topology():

    net = Mininet(controller=RemoteController, link=TCLink, switch=OVSKernelSwitch)

    s1 = net.addSwitch('s1', listenPort=6673, mac='00:00:00:00:00:01')
    s2 = net.addSwitch('s2', listenPort=6674, mac='00:00:00:00:00:02')
    h1 = net.addHost('h1', mac='00:00:00:00:00:01', ip='10.0.0.1/24')
    h2 = net.addHost('h2', mac='00:00:00:00:00:02', ip='10.0.0.2/24')
    c10 = net.addController('c10', controller=RemoteController, ip='127.0.0.1', port=6633)
    c11 = net.addController('c11', controller=RemoteController, ip='127.0.0.1', port=5566)

    linkBW = {'bw':1}
    net.addLink(s1, h1, cls=TCLink, **linkBW)
    net.addLink(s2, h2, cls=TCLink, **linkBW)
    net.addLink(s1, s2, cls=TCLink, **linkBW)

    net.build()
    c10.start()
    c11.start()
    s1.start([c10,c11])
    s2.start([c10,c11])
    CLI(net)

    net.stop()

if __name__ == '__main__':
    topology()

