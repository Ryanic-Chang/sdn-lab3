from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet
from os_ken.lib.packet import ethernet, arp, ipv4
from os_ken.lib.packet import ether_types
from os_ken import log

# 引入 NetworkAwareness
from controllers.task3.network_awareness import NetworkAwareness

ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"
ARP = arp.arp.__name__

class ShortestTimeDelay(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"network_awareness": NetworkAwareness}

    def __init__(self, *args, **kwargs):
        super(ShortestTimeDelay, self).__init__(*args, **kwargs)
        self.network_awareness = kwargs["network_awareness"]
        # 指定寻路算法以时延 delay 作为权重
        self.network_awareness.weight = 'delay'
        self.mac_to_port = {}
        self.sw = {}  # 记录 ARP 洪泛，防止环路风暴

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority,
            idle_timeout=idle_timeout, hard_timeout=hard_timeout,
            match=match, instructions=inst
        )
        datapath.send_msg(mod)

    # 主机注册时的控制台输出，调用拓扑打印
    def register_host(self, dpid, in_port, ip):
        na = self.network_awareness
        if ip not in na.topo_map:
            na.topo_map.add_edge(ip, dpid, hop=1, delay=0, is_host=True)
            na.link_info[(dpid, ip)] = in_port
            
            # 展示当前最新的拓扑图结构
            self.logger.info(f"host: {ip} bind to switch s{dpid}")
            na.show_topo_map()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        if not eth_pkt:
            return
        # 忽略控制平面的拓扑发现包，避免干扰数据平面流表
        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP or eth_pkt.ethertype == ether_types.ETH_TYPE_IPV6:
            return  

        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        pkt_type = eth_pkt.ethertype
        dst_mac = eth_pkt.dst
        src_mac = eth_pkt.src

        if arp_pkt:
            self.handle_arp(msg, in_port, dst_mac, src_mac, pkt, pkt_type)

        if ipv4_pkt:
            self.handle_ipv4(msg, ipv4_pkt.src, ipv4_pkt.dst, pkt_type)

    def handle_arp(self, msg, in_port, dst, src, pkt, pkt_type):
        dp = msg.datapath
        dpid = dp.id
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        header_list = dict((p.protocol_name, p) for p in pkt.protocols if type(p) != str)
        if ARP in header_list:
            arp_packet = header_list[ARP]
            
            # 任何 ARP 报文都主动记录其发送方主机，加速全网拓扑构建
            self.register_host(dpid, in_port, arp_packet.src_ip)
            
            if dst == ETHERNET_MULTICAST and arp_packet.opcode == arp.ARP_REQUEST:
                dst_ip = arp_packet.dst_ip
                if (dpid, src, dst_ip) in self.sw:
                    if self.sw[(dpid, src, dst_ip)] != in_port:
                        return # 检测到物理环路传回来的相同请求，直接丢弃
                else:
                    self.sw[(dpid, src, dst_ip)] = in_port

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=pkt_type)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(dp, 1, match, actions, 10, 30)

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port, actions=actions, data=msg.data
        )
        dp.send_msg(out)

    def handle_ipv4(self, msg, src_ip, dst_ip, pkt_type):
        dp = msg.datapath
        dpid = dp.id
        parser = dp.ofproto_parser
        in_port = msg.match['in_port']
        
        # 拦截到 IPv4 时，确保发起方已被录入图结构
        self.register_host(dpid, in_port, src_ip)

        # 基于 delay 权重进行 Dijkstra 最短路径计算
        dpid_path = self.network_awareness.shortest_path(src_ip, dst_ip, weight='delay')
        if not dpid_path or len(dpid_path) < 2:
            return
    
        port_path = []
        for i in range(len(dpid_path)):
            node = dpid_path[i]
            if isinstance(node, str):
                continue
                
            in_p = None
            out_p = None
            
            # 确定每一个交换机的入端口和出端口
            if i == 1:  
                in_p = self.network_awareness.link_info.get((node, src_ip))
                if len(dpid_path) > 2:
                    out_p = self.network_awareness.link_info.get((node, dpid_path[2]))
            elif i == len(dpid_path) - 2:  
                in_p = self.network_awareness.link_info.get((node, dpid_path[i-1]))
                out_p = self.network_awareness.link_info.get((node, dst_ip))
            else:  
                in_p = self.network_awareness.link_info.get((node, dpid_path[i-1]))
                out_p = self.network_awareness.link_info.get((node, dpid_path[i+1]))
            
            if in_p is not None and out_p is not None:
                port_path.append((in_p, node, out_p))
    
        if not port_path:
            return
    
        # 打印日志
        self.show_path(src_ip, dst_ip, port_path)
    
        # 沿着路径双向下发流表
        for in_p, switch_dpid, out_p in port_path:
            self.send_flow_mod(parser, switch_dpid, pkt_type, src_ip, dst_ip, in_p, out_p)
            self.send_flow_mod(parser, switch_dpid, pkt_type, dst_ip, src_ip, out_p, in_p)
    
        # 由最后一跳交换机发送数据包
        last_hop = port_path[-1]
        target_dp = self.network_awareness.switch_info.get(last_hop[1])
        if target_dp:
            actions = [parser.OFPActionOutput(last_hop[2])]
            out = parser.OFPPacketOut(
                datapath=target_dp, 
                buffer_id=target_dp.ofproto.OFP_NO_BUFFER, 
                in_port=target_dp.ofproto.OFPP_CONTROLLER, 
                actions=actions, 
                data=msg.data
            )
            target_dp.send_msg(out)

    def send_flow_mod(self, parser, dpid, pkt_type, src_ip, dst_ip, in_port, out_port):
        dp = self.network_awareness.switch_info.get(dpid)
        if not dp:
            return

        match = parser.OFPMatch(
            in_port=in_port, eth_type=pkt_type,
            ipv4_src=src_ip, ipv4_dst=dst_ip
        )
        actions = [parser.OFPActionOutput(out_port)]
        # 设置流表优先级和老化时间
        self.add_flow(dp, 1, match, actions, 10, 30)

    def show_path(self, src, dst, port_path):
        """打印最终经过的路线及预估的时延"""
        total_delay = 0
        for i in range(len(port_path)-1):
            dpid1 = port_path[i][1]
            dpid2 = port_path[i+1][1]
            if (dpid1 in self.network_awareness.topo_map and 
                dpid2 in self.network_awareness.topo_map and 
                self.network_awareness.topo_map.has_edge(dpid1, dpid2)):
                total_delay += self.network_awareness.topo_map[dpid1][dpid2].get('delay', 0)

        path_str = f"{src} -> "
        for node in port_path:
            path_str += f"s{node[1]} -> "
        path_str += dst

        self.logger.info(f"Optimal Path (Delay): {path_str} | Estimated Total Delay: {total_delay*1000:.2f} ms\n")


if __name__ == '__main__':
    from os_ken import cfg
    import os_ken.topology.switches
    cfg.CONF.observe_links = True
    
    log.init_log()
    app_manager.AppManager.run_apps([
        "controllers.task3.shortest_time_delay",
        "os_ken.topology.switches"
    ])