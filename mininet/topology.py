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
from mininet.topo import Topo


class Topology(Topo):

    def __init__(self):
        super(Topology, self).__init__()
        self.graph = None

    def build(self):

        # # parse internet topology zoo graph
        # # note: requires at least 8GB of RAM
        # self.graph = fnss.parse_topology_zoo('topology_zoo/AttMpls.graphml')

        # build scale free graph with 5 nodes for testing
        self.graph = nx.barabasi_albert_graph(n=5, m=2, seed=1234)

        self.add_switches()
        self.add_links()

    def add_switches(self):
        # create switches and attach a host to the switch
        # one host per switch
        for node in self.graph.nodes():
            # start index from 1
            node = node + 1

            # add switch
            self.addSwitch('s%d' % node)

            # add host
            self.addHost('h%d' % node)

            # add host -- switch link
            self.addLink("s%d" % node, "h%d" % node)

    def add_links(self):

        for (u, v) in self.graph.edges():

            # start index from 1
            u = u + 1
            v = v + 1

            # # add TCLink parameters for mininet here
            # # calculations according to Auto-Mininet paper by Grobmann et al.
            # linkopts = {'bw': bandwidth, 'delay': delay, 'max_queue_size': 1000, 'use_htb': True}

            # # add switch -- switch link
            # self.addLink("s%d" % u, "s%d" % v, **linkopts)

            self.addLink("s%d" % u, "s%d" % v)


if __name__ == '__main__':

    setLogLevel('info')
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--controller", help="ip address of sdn controller", default='127.0.0.1')
    args = parser.parse_args()

    topology = Topology()
    topology.build()

    net = Mininet(topo=topology, controller=None, host=CPULimitedHost, link=TCLink, switch=OVSSwitch, autoSetMacs=True)
    net.addController('c1', controller=RemoteController, ip=args.controller, port=6633)
    net.start()
    CLI(net)
    net.stop()


