#include <core.p4>
#include <v1model.p4>
// 定义以太网头
header ethernet_h {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

// 定义headers结构体
struct headers {
    ethernet_h ethernet;
}

// 元数据（若无特殊需求可留空）
struct metadata { }

// 解析器
parser MyParser(
    packet_in packet,
    out headers hdr,
    inout metadata meta,
    inout standard_metadata_t std_meta
) {
    state start {
        packet.extract(hdr.ethernet);  // 提取以太网头
        transition accept;
    }
}
//////////////
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {  
    apply {  }
}
//////////
control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t std_meta) {
    action forward(bit<9> port) {
        std_meta.egress_spec = port;
    }
    action drop(){
	mark_to_drop(std_meta);
}
    table mac_forward {
        key = { hdr.ethernet.dstAddr: exact; }
        actions = { forward; drop; }
        size = 1024;
        default_action = drop();
    }

    apply {
        mac_forward.apply();
    }
}
/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
      packet.emit(hdr.ethernet);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
