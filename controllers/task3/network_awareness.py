from os_ken.base import app_manager
from os_ken.base.app_manager import lookup_service_brick
from os_ken.ofproto import ofproto_v1_3
from os_ken.controller.handler import set_ev_cls
from os_ken.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from os_ken.controller import ofp_event
from os_ken.lib.packet import packet
from os_ken.lib.packet import ethernet, arp
from os_ken.lib import hub
from os_ken.topology import event
from os_ken.topology.api import get_host, get_link, get_switch
from os_ken.topology.switches import LLDPPacket
import os_ken.topology.switches

import networkx as nx
import copy
import time


GET_TOPOLOGY_INTERVAL = 2
SEND_ECHO_REQUEST_INTERVAL = .05
GET_DELAY_INTERVAL = 2


class NetworkAwareness(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'switches': os_ken.topology.switches.Switches}

    def __init__(self, *args, **kwargs):
        super(NetworkAwareness, self).__init__(*args, **kwargs)
        self.switch_info = {}  # dpid: datapath
        self.link_info = {}  # (s1, s2): s1.port
        self.port_link={} # s1,port:s1,s2
        self.port_info = {}  # dpid: (ports linked hosts)
        self.topo_map = nx.Graph()
        self.topo_thread = hub.spawn(self._get_topology)


        self.weight = 'delay'
        # 初始化时延测量的数据结构与线程
        self.echo_delay = {}  # dpid: echo_delay
        self.lldp_delay = {}  # (src_dpid, dst_dpid): lldp_delay
        self.switches = None
        self.echo_thread = hub.spawn(self._send_echo_request)
        self.delay_thread = hub.spawn(self._measure_delay)

    def add_flow(self, datapath, priority, match, actions):
        dp = datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match, instructions=inst)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        dp = ev.datapath
        dpid = dp.id

        if ev.state == MAIN_DISPATCHER:
            self.switch_info[dpid] = dp

        if ev.state == DEAD_DISPATCHER:
            del self.switch_info[dpid]
    def _get_topology(self):
        hub.sleep(0.1)  # wait for other apps to initialize
        _hosts, _switches, _links = None, None, None
        while True:
            hosts = get_host(self)
            switches = get_switch(self)
            links = get_link(self)

            # update topo_map when topology change
            if [str(x) for x in hosts] == _hosts and [str(x) for x in switches] == _switches and [str(x) for x in links] == _links:
                hub.sleep(GET_TOPOLOGY_INTERVAL)
                continue
            _hosts, _switches, _links = [str(x) for x in hosts], [str(x) for x in switches], [str(x) for x in links]

            for switch in switches:
                self.port_info.setdefault(switch.dp.id, set())
                # record all ports
                for port in switch.ports:
                    self.port_info[switch.dp.id].add(port.port_no)

            for host in hosts:
                # take one ipv4 address as host id
                if host.ipv4:
                    self.link_info[(host.port.dpid, host.ipv4[0])] = host.port.port_no
                    self.topo_map.add_edge(host.ipv4[0], host.port.dpid, hop=1, delay=0, is_host=True)
            for link in links:
                # delete ports linked switches
                self.port_info[link.src.dpid].discard(link.src.port_no)
                self.port_info[link.dst.dpid].discard(link.dst.port_no)

                # s1 -> s2: s1.port, s2 -> s1: s2.port
                self.port_link[(link.src.dpid,link.src.port_no)]=(link.src.dpid, link.dst.dpid)
                self.port_link[(link.dst.dpid,link.dst.port_no)] = (link.dst.dpid, link.src.dpid)

                self.link_info[(link.src.dpid, link.dst.dpid)] = link.src.port_no
                self.link_info[(link.dst.dpid, link.src.dpid)] = link.dst.port_no
                self.topo_map.add_edge(link.src.dpid, link.dst.dpid, hop=1, is_host=False)

            if self.weight == 'delay':
                self.show_topo_map()
            hub.sleep(GET_TOPOLOGY_INTERVAL)

    def shortest_path(self, src, dst, weight='hop'):
        try:
            paths = list(nx.shortest_simple_paths(self.topo_map, src, dst, weight=weight))
            return paths[0]
        except:
            self.logger.info('host not find/no path')

    def show_topo_map(self):
        self.logger.info('topo map:')
        self.logger.info('{:^10s}  ->  {:^10s}'.format('node', 'node'))
        for src, dst in self.topo_map.edges:
            self.logger.info('{:^10s}      {:^10s}'.format(str(src), str(dst)))
        self.logger.info('\n')
    
    # 时延测量方法 
    def _send_echo_request(self):
        """周期性向下发 Echo Request，携带当前时间戳"""
        while True:
            for dp in self.switch_info.values():
                parser = dp.ofproto_parser
                data = str(time.time()).encode('utf-8')
                echo_req = parser.OFPEchoRequest(dp, data=data)
                dp.send_msg(echo_req)
            hub.sleep(SEND_ECHO_REQUEST_INTERVAL)

    @set_ev_cls(ofp_event.EventOFPEchoReply, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def echo_reply_handler(self, ev):
        """处理 Echo Reply 报文，得出 Echo Delay"""
        now = time.time()
        try:
            send_time = float(ev.msg.data)
            echo_delay = now - send_time
            self.echo_delay[ev.msg.datapath.id] = echo_delay
        except:
            pass

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_hander(self, ev):
        """处理 PacketIn 中的 LLDP 报文，提取经过 switches.py 计算的延迟"""
        msg = ev.msg
        dpid = msg.datapath.id
        try:
            src_dpid, src_port_no = LLDPPacket.lldp_parse(msg.data)
            if self.switches is None:
                self.switches = lookup_service_brick('switches')
            for port in self.switches.ports.keys():
                if src_dpid == port.dpid and src_port_no == port.port_no:
                    self.lldp_delay[(src_dpid, dpid)] = self.switches.ports[port].delay
        except:
            return

    def _measure_delay(self):
        """周期性计算各个链路的总时延并更新至拓扑图的有权边"""
        while True:
            hub.sleep(GET_DELAY_INTERVAL)
            for src, dst in self.topo_map.edges:
                if self.topo_map[src][dst].get('is_host', False):
                    continue
                
                # 提取参数
                lldp_12 = self.lldp_delay.get((src, dst), 0)
                lldp_21 = self.lldp_delay.get((dst, src), 0)
                echo_1 = self.echo_delay.get(src, 0)
                echo_2 = self.echo_delay.get(dst, 0)

                # 公式计算
                delay = (lldp_12 + lldp_21 - echo_1 - echo_2) / 2
                delay = max(delay, 0)  # 防止出现负数
                
                # 更新权重
                self.topo_map[src][dst]['delay'] = delay