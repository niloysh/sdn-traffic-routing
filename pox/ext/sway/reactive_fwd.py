import networkx as nx
import random
import pox.openflow.libopenflow_01 as of

from collections import defaultdict
from pox.core import core
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.arp import arp
from pox.lib.recoco import Timer
from pox.lib.revent import EventMixin
from pox.openflow import ethernet

log = core.getLogger()


IDLE_TIMEOUT = 10
INTERVAL = 5

class SwitchWithPaths(EventMixin):

    def __init__(self, dpid):
        super(SwitchWithPaths, self).__init__()
        self.connection = None
        self.ports = None
        self.dpid = dpid
        self._listeners = None
        self._connected_at = None
        self.paths = {}


    def connect(self, connection):
        if self.dpid is None:
            self.dpid = connection.dpid
        assert (self.dpid == connection.dpid)
        if self.ports is None:
            self.ports = connection.features.ports
        log.info("Connect %s" % connection)
        self.connection = connection
        self._listeners = self.listenTo(connection)

    def disconnect(self):
        if self.connection is not None:
            log.info("Disconnect %s" % self.connection)
            self.connection.removeListeners(self._listeners)
            self.connection = None
            self._listeners = None

    def install_output_flow_rule(self, outport, match, idle_timeout=0):
        try:
            msg = of.ofp_flow_mod()
            msg.match = match
            msg.command = of.OFPFC_MODIFY_STRICT
            msg.idle_timeout = idle_timeout
            msg.actions.append(of.ofp_action_output(port=outport))
            # raise event when flow is removed
            msg.flags = of.OFPFF_SEND_FLOW_REM
            # unique flow identifier
            msg.cookie = random.getrandbits(32)
            self.connection.send(msg)

        except Exception:
            log.warn('Failed to install output rule at switch {}'.format(self.dpid))


    def install_drop_flow_rule(self, match, idle_timeout=0):
        msg = of.ofp_flow_mod()
        msg.match = match
        msg.command = of.OFPFC_MODIFY_STRICT
        msg.idle_timeout = idle_timeout
        msg.actions = []  # empty action list for dropping packets
        self.connection.send(msg)

    def delete_flow_rule(self, match):
        msg = of.ofp_flow_mod()
        msg.match = match
        msg.command = of.OFPFC_DELETE_STRICT
        self.connection.send(msg)

    def send_packet(self, outport, packet_data=None):
        msg = of.ofp_packet_out(in_port=of.OFPP_NONE)
        msg.data = packet_data
        msg.actions.append(of.ofp_action_output(port=outport))
        self.connection.send(msg)


    def flood_on_switch_edge(self, packet, no_flood_ports):
        for no_flood in self.ports:  # flood arp req in all ports to know mac and ip adress
            if no_flood.port_no not in no_flood_ports and no_flood.port_no != 65534:
                self.send_packet(no_flood.port_no, packet)

    def send_arp_reply(self, packet, dst_port, req_mac):
        log.debug("Sending ARP Reply for %s" % req_mac)
        r = arp()
        r.hwtype = r.HW_TYPE_ETHERNET  # type of hardware tyr
        r.prototype = r.PROTO_TYPE_IP  # protocolo type
        r.hwlen = 6  # hardware addrese length 6 bytes and mac=ipv6
        r.protolen = r.protolen  # the ipv4 length
        r.opcode = r.REPLY  # the packet has Reply type

        r.hwdst = packet.payload.hwsrc
        r.hwsrc = req_mac  # fake mac

        # Reverse the src , dest to have an answer
        r.protosrc = packet.payload.protodst
        r.protodst = packet.payload.protosrc

        e = ethernet(type=packet.ARP_TYPE, src=req_mac, dst=packet.payload.hwsrc)
        e.set_payload(r)

        msg = of.ofp_packet_out()
        msg.data = e.pack()
        # send the message through the client outport
        msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))  # in which port clients can hear
        msg.in_port = dst_port
        self.connection.send(msg)

    def appendPaths(self, dst, paths_list):
        if dst not in self.paths:
            self.paths[dst] = []
        self.paths[dst] = paths_list

    def clearPaths(self):
        self.paths = {}

    def printPaths(self):
        pass


class ReactiveForwarding(EventMixin):
    _neededComponents = {'openflow_discovery'}

    def __init__(self):
        super(ReactiveForwarding, self).__init__()

        # generic controller information
        self.switches = {}  # key=dpid, value = SwitchWithPaths instance
        self.sw_sw_ports = {}  # key = (dpid1,dpid2), value = outport of dpid1
        self.sw_port_sw = {}  # key = (dpid1, outport) , value = dpid2
        self.adjs = {}  # key = dpid, value = list of neighbors
        self.arpmap = {}  # key=host IP, value = (mac,dpid,port)
        self.ignored_IPs = [IPAddr("0.0.0.0"), IPAddr("255.255.255.255")]  # these are used by openflow discovery module
        self.graph = nx.DiGraph()  # graph global

        # measure bandwidth utilization
        # key = dpid, value = dict( key = port, value = last seen bytes)
        self.sw_port_bytes = defaultdict(lambda: defaultdict(int))

        # key = dpid, value = dict( key = port, value = bandwidth utilization)
        self.sw_port_util = defaultdict(lambda: defaultdict(int))

        # timers
        # Timer(5, self.stats_timer, recurring=True)

        # invoke event listeners
        if not core.listen_to_dependencies(self, self._neededComponents):
            self.listenTo(core)
        self.listenTo(core.openflow)

        # core.openflow.addListener(FlowStatsReceived, self._handle_openflow_FlowStatsReceived)
        log.info("Started ReactiveForwarding!")

        # statistics
        self.num_ip_pktin = 0


    @staticmethod
    def create_switch(dpid):
        return SwitchWithPaths(dpid)

    def _handle_ConnectionUp(self, event):
        if event.dpid not in self.switches:
            self.switches[event.dpid] = self.create_switch(dpid=event.dpid)
            if event.dpid not in self.adjs:
                self.adjs[event.dpid] = set([])
        self.switches[event.dpid].connect(event.connection)

        # send unknown ARP and IP packets to controller (install rules for that with low priority)
        msg_ARP = of.ofp_flow_mod()
        msg_IP = of.ofp_flow_mod()
        msg_ARP.match.dl_type = 0x0806
        msg_IP.match.dl_type = 0x0800
        msg_ARP.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        msg_IP.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        msg_ARP.priority = of.OFP_DEFAULT_PRIORITY - 1
        msg_IP.priority = of.OFP_DEFAULT_PRIORITY - 1
        event.connection.send(msg_ARP)
        event.connection.send(msg_IP)

    def _handle_ConnectionDown(self, event):
        ips_to_forget = []
        for ip in self.arpmap:
            (mac, dpid, port) = self.arpmap[ip]
            if dpid == event.dpid:
                ips_to_forget.append(ip)
        for ip in ips_to_forget:
            del self.arpmap[ip]
        if event.dpid in self.switches:
            self.switches[event.dpid].disconnect()
            del self.switches[event.dpid]
            # let the discovery module deal with the port removals...

    def flood_on_all_switch_edges(self, packet, this_dpid, this_port):
        for src_dpid in self.switches:
            no_flood_ports = set([])  # list of non-flood ports
            if src_dpid in self.adjs:
                for nei_dpid in self.adjs[src_dpid]:
                    no_flood_ports.add(self.sw_sw_ports[(src_dpid, nei_dpid)])
            if src_dpid == this_dpid:
                no_flood_ports.add(this_port)
            self.switches[src_dpid].flood_on_switch_edge(packet, no_flood_ports)

    def update_learned_arp_info(self, packet, dpid, port):
        log.debug("Updating ARP table for switch %s" % dpid)
        src_ip = None
        src_mac = None
        if packet.type == packet.ARP_TYPE:
            src_mac = EthAddr(packet.src)
            src_ip = IPAddr(packet.next.protosrc)
        elif packet.type == packet.IP_TYPE:
            src_mac = EthAddr(packet.src)
            src_ip = IPAddr(packet.next.srcip)
        else:
            pass
        if (src_ip is not None) and (src_mac is not None):
            self.arpmap[src_ip] = (src_mac, dpid, port)

    def handle_ARP_pktin(self, event):
        packet = event.parsed
        dpid = event.dpid
        inport = event.port

        srcip = IPAddr(packet.next.protosrc)
        dstip = IPAddr(packet.next.protodst)
        if (srcip in self.ignored_IPs) or (dstip in self.ignored_IPs):
            return

        if packet.next.opcode == arp.REQUEST:
            log.debug("Handling ARP packet: %s requests the MAC of %s" % (str(srcip), str(dstip)))
            self.update_learned_arp_info(packet, dpid, inport)

            if dstip in self.arpmap:
                log.debug("I know where to send the crafted ARP reply!")
                (req_mac, req_dpid, req_port) = self.arpmap[dstip]
                (dst_mac, dst_dpid, dst_port) = self.arpmap[srcip]
                self.switches[dst_dpid].send_arp_reply(packet, dst_port, req_mac)
            else:
                log.debug("Flooding initial ARP request on all switch edges")
                self.flood_on_all_switch_edges(packet, dpid, inport)

        elif packet.next.opcode == arp.REPLY:
            log.debug("Handling ARP packet: %s responds to %s" % (str(srcip), str(dstip)))
            self.update_learned_arp_info(packet, dpid, inport)

            if dstip in self.arpmap.keys():
                log.debug("I know where to send the initial ARP reply!")
                (dst_mac, dst_dpid, dst_port) = self.arpmap[dstip]
                self.switches[dst_dpid].send_packet(dst_port, packet)
            else:
                log.debug("Flooding initial ARP reply on all switch edges")
                self.flood_on_all_switch_edges(packet, dpid, inport)
        else:
            log.warn("Unknown ARP type")
            return

    def handle_IP_pktin(self, event):

        self.num_ip_pktin += 1

        packet = event.parsed
        dpid = event.dpid
        inport = event.port

        srcip = IPAddr(packet.next.srcip)
        dstip = IPAddr(packet.next.dstip)
        if (srcip in self.ignored_IPs) or (dstip in self.ignored_IPs):
            return

        # I know where to send the packet
        if dstip in self.arpmap:
            (dst_mac, dst_dpid, dst_port) = self.arpmap[dstip]

            if dpid == dst_dpid:
                self.install_path(event, dst_dpid, dst_port)
            else:
                if self.shortestPath(event, dst_dpid):
                    self.install_path(event, dst_dpid, dst_port)
                else:
                    log.warn("No path for flow %s-->%s, discarding packet" % (dpid, dst_dpid))
                    return
        else:
            self.flood_on_all_switch_edges(packet, dpid, inport)

    def _handle_PacketIn(self, event):
        packet = event.parsed

        if packet.type == packet.LLDP_TYPE:
            return

        elif packet.type == packet.ARP_TYPE:
            self.handle_ARP_pktin(event)
            return

        elif packet.type == packet.IP_TYPE:
            self.handle_IP_pktin(event)
            return

        else:
            log.warn("Unknown Packet type: %s" % packet.type)
            return

    def install_path(self, event, dst_dpid, final_port):
        source_switch = event.dpid  # take the switch node triggered the event
        dest_switch = dst_dpid  # take the destination node switch
        packet = event.parsed
        in_port = event.port

        match = of.ofp_match.from_packet(packet, in_port)
        # match.tp_src = None

        if source_switch == dest_switch:
            # means that we are in the same switch edge
            self.switches[source_switch].install_output_flow_rule(final_port, match, IDLE_TIMEOUT)
            self.switches[source_switch].send_packet(final_port, event.data)


        else:
            path = self.switches[source_switch].paths[dest_switch]
            last_index = len(path) - 1  # last path index
            path_length = len(path)

            # install rules from last switch to minimize packet in while flow-mod is on the way
            for index in range(path_length):
                reverse_index = last_index - index  # go to the last index

                if reverse_index != last_index:
                    # else if we are in the other switches
                    outport = self.sw_sw_ports[(path[reverse_index], path[reverse_index + 1])]
                else:
                    outport = final_port  # if we are in the last switch

                if reverse_index != 0:
                    inport = self.sw_sw_ports[(path[reverse_index], path[reverse_index - 1])]
                else:
                    # we are in the first switch
                    inport = event.port

                match = of.ofp_match.from_packet(packet, inport)
                match.tp_src = None
                self.switches[path[reverse_index]].install_output_flow_rule(outport, match, IDLE_TIMEOUT)

            # send the packet which caused packet-in
            self.switches[source_switch].send_packet(self.sw_sw_ports[(source_switch, path[1])], event.data)

    def _handle_openflow_discovery_LinkEvent(self, event):

        link = event.link
        dpid1 = link.dpid1
        port1 = link.port1
        dpid2 = link.dpid2
        port2 = link.port2
        if dpid1 not in self.adjs:
            self.adjs[dpid1] = set([])
        if dpid2 not in self.adjs:
            self.adjs[dpid2] = set([])

        if event.added:
            self.sw_sw_ports[(dpid1, dpid2)] = port1
            self.sw_sw_ports[(dpid2, dpid1)] = port2
            self.adjs[dpid1].add(dpid2)
            self.adjs[dpid2].add(dpid1)
            self.sw_port_sw[(dpid1, port1)] = dpid2
            self.sw_port_sw[(dpid2, port2)] = dpid1

            for adj in self.adjs:  # take nodes
                if not self.graph.has_node(adj):
                    self.graph.add_node(adj)  # take link to nodes

                for links in self.adjs.get(adj):
                    if not self.graph.has_edge(adj, links):
                        self.graph.add_edge(adj, links)

        # fixme: timeout due to excess load leads to keyerror
        # if we increase timeout period, discovery takes a long time
        # see openflow.discovery
        # for now, the timeout logging has been disabled
        # and the networkx graph is not cleared
        # however, this may cause unforeseen problems

        else:
            if (dpid1, dpid2) in self.sw_sw_ports:
                del self.sw_sw_ports[(dpid1, dpid2)]
            if (dpid2, dpid1) in self.sw_sw_ports:
                del self.sw_sw_ports[(dpid2, dpid1)]
            if dpid2 in self.adjs[dpid1]:
                self.adjs[dpid1].remove(dpid2)
            if dpid1 in self.adjs[dpid2]:
                self.adjs[dpid2].remove(dpid1)



    def shortestPath(self, event, dest_switch):
        source_switch = event.dpid
        switches = self.switches

        try:

            path = nx.dijkstra_path(self.graph, source_switch, dest_switch)
            log.debug("Calculated path: %s" % path)
            switches[source_switch].appendPaths(dest_switch, path)


        # catch possible networkx no path exception
        except Exception as e:
            log.error('Networkx no path found')
            log.error(e, exc_info=True)
            return False

        return True  # shortest path exists



def launch():
    core.registerNew(ReactiveForwarding)  # register new component in core
