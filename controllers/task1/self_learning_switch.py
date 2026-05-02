from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet
from os_ken.lib.packet import ethernet
from os_ken import log

class Switch(app_manager.OSKenApp):
    
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    def __init__(self, *args, **kwargs):
        super(Switch, self).__init__(*args, **kwargs)
        # maybe you need a global data structure to save the mapping
        # 初始化一个字典保存每个交换机的 mac_to_port 映射
        self.mac_to_port = {}
        
    def add_flow(self, datapath, priority, match, actions,idle_timeout=0,hard_timeout=0):
        dp = datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match,instructions=inst)
        dp.send_msg(mod)
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,ofp.OFPCML_NO_BUFFER)]
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
        # get the mac
        dst = eth_pkt.dst
        src = eth_pkt.src
        # we can use the logger to print some useful information
        self.logger.info('packet: %s %s %s %s', dpid, src, dst, in_port)
        
        # You need to code here to avoid the direct flooding
        # Have fun!
        # :)
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
        # 后续同类的报文不需要再上送控制器（Packet-In），而是直接由交换机硬件转发
        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # 下发的流表优先级必须大于默认的 Table-Miss 流表（优先级为0），此处设为1
            self.add_flow(dp, 1, match, actions)

        # 5.让交换机把当前被拦截的包发出去
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
    app_manager.AppManager.run_apps(["controllers.task1.self_learning_switch"])