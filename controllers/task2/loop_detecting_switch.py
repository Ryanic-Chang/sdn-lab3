from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import arp
from os_ken.lib.packet import ether_types
from os_ken import log

ETHERNET = ethernet.ethernet.__name__
ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"
ARP = arp.arp.__name__


class Switch_Dict(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Switch_Dict, self).__init__(*args, **kwargs)
        self.sw = {} #(dpid, src_mac, dst_ip)=>in_port, you may use it in task 2
        # maybe you need a global data structure to save the mapping
        # just data structure in task 1
        # 从 Task 1 引入的二层自学习 MAC 表
        self.mac_to_port = {}

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        dp = datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # the identity of switch
        dpid = dp.id
        # the port that receive the packet
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        if eth_pkt.ethertype == ether_types.ETH_TYPE_IPV6:
            return
        # get the mac
        dst = eth_pkt.dst
        src = eth_pkt.src
        # get protocols
        header_list = dict((p.protocol_name, p) for p in pkt.protocols if type(p) != str)
        # you need to code here to avoid broadcast loop to finish task 2
        if dst == ETHERNET_MULTICAST and ARP in header_list:
            arp_pkt = header_list[ARP]
            # 只拦截和处理 ARP 请求报文 (opcode=1)
            if arp_pkt.opcode == arp.ARP_REQUEST:
                dst_ip = arp_pkt.dst_ip
                # 构建唯一映射 Key
                key = (dpid, src, dst_ip)
                
                if key in self.sw:
                    # 之前记录过相同的请求，如果这次的入端口不同，说明这是绕着环路洪泛回来的包
                    if self.sw[key] != in_port:
                        self.logger.info("ARP Loop Detected & Dropped: %s asking for %s on dpid %s", src, dst_ip, dpid)
                        return # 直接丢弃，中止执行，不向交换机发送 PacketOut
                else:
                    # 第一次收到，记录映射并继续后续洪泛动作
                    self.sw[key] = in_port
        # self-learning
        # you need to code here to avoid the direct flooding
        # having fun
        # :)
        # just code in task 1
        # 1. 为当前交换机初始化 mac_to_port 字典
        self.mac_to_port.setdefault(dpid, {})

        # 2. 将源 MAC 地址与入端口绑定
        self.mac_to_port[dpid][src] = in_port

        # 3. 查询目的 MAC 地址是否已学习
        if dst in self.mac_to_port[dpid]:
            # 单播转发至指定端口
            out_port = self.mac_to_port[dpid][dst]
        else:
            # 全网洪泛(入端口除外)
            out_port = ofp.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # 4. 如果不是洪泛（即已知道目的端口），则向交换机下发流表
        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(dp, 1, match, actions)

        # 5. 让交换机把当前处理完的包发出去
        out = parser.OFPPacketOut(
            datapath=dp, 
            buffer_id=ofp.OFP_NO_BUFFER, 
            in_port=in_port, 
            actions=actions, 
            data=msg.data
        )
        dp.send_msg(out)

if __name__ == '__main__':
    log.init_log()
    app_manager.AppManager.run_apps(["controllers.task2.loop_detecting_switch"])