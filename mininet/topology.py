import argparse
import fnss
import random
import networkx as nx

# mininet imports
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.util import dumpNodeConnections
from mininet.topo import Topo


class CustomTopology(Topo):

    def build(self):

        print "Building topology"

        self.graph = nx.barabasi_albert_graph(n=3, m=1, seed=1234)
        n = nx.number_of_nodes(self.graph)
        host_id = 1

        for node_id in self.graph.nodes():
            self.addSwitch('s%d' % node_id)

            # each host gets 50%/n of CPU
            self.addHost('h%d' % node_id, cpu = 0.5/n)
            self.addLink("s%d" % node_id, "h%d" % host_id)
            host_id += 1

        for (u, v) in self.graph.edges():
            self.addLink("s%d" % u, "s%d" % v)


if __name__ == '__main__':

    setLogLevel('info')
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--controller", help="ip address of sdn controller", default='127.0.0.1')
    args = parser.parse_args()

    topology = CustomTopology()

    net = Mininet(topo=topology,
                  controller=RemoteController('c1', ip=args.controller, port=6633),
                  host=CPULimitedHost,
                  link=TCLink,
                  switch=OVSSwitch,
                  autoSetMacs=True)

    # disable ipv6
    print "Disabling ipv6 on all switches and hosts"
    for h in net.hosts:
        print "disable ipv6"
        h.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        h.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        h.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

    for sw in net.switches:
        print "disable ipv6"
        sw.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        sw.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        sw.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")


    net.start()

    print "Dumping host connections"
    dumpNodeConnections(net.hosts)

    CLI(net)

    net.stop()


