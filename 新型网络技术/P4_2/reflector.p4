#include <core.p4>
#include <v1model.p4>

header ethernet_h {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_h {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

struct metadata { /* 空元数据 */ }
struct headers { ethernet_h ethernet; ipv4_h ipv4; }

parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t std_meta) {
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800 : parse_ipv4;
            default : accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t std_meta) {
    action swap_addresses() {
        // 交换MAC和IP地址
        bit<48> tmp_mac = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = tmp_mac;

        bit<32> tmp_ip = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = tmp_ip;

        // 从接收端口返回
        std_meta.egress_spec = std_meta.ingress_port;
    }

    apply {
        if (hdr.ipv4.isValid()) {
            swap_addresses();
        }
    }
}

control MyEgress(...) { /* 无需操作 */ }

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyDeparser()) main;
