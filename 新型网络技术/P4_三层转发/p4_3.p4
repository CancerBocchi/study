/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    bit<48>	dstAddr;
    bit<48>	srcAddr;
    bit<16>	etherType;
}

header ipv4_t {
    bit<4>       version;
    bit<4>       ihl;
    bit<8>       diffserv;
    bit<16>      totalLen;
    bit<16>      identification;
    bit<3>       flags;
    bit<13>      fragOffset;
    bit<8>       ttl;
    bit<8>       protocol;
    bit<16>      hdrChecksum;
    bit<32>      srcAddr;
    bit<32>      dstAddr;
}

header arp_t {
	bit<16>      h_type;
	bit<16>      proto_type;
	bit<8>       Addr_len;
	bit<8>       protoAddr_len;
	bit<16>      op_code;
	bit<48>      src_mac;
	bit<32>      src_ip;
	bit<48>      dst_mac;
	bit<32>      dst_ip;
}

header icmp_t {
    bit<8>    type;
    bit<8>    code;
    bit<16>   hdrChecksum;
    bit<16>   identifier;
    bit<16>   sequence_number;
}

struct metadata {
    /* empty */
}


struct headers {
  ethernet_t   ethernet;
  ipv4_t ipv4;
  arp_t arp;
  icmp_t icmp;
}

 

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) 
{
    @name("_parse_ethernet") state parse_ethernet
	{
		packet.extract(hdr.ethernet);
		transition select(hdr.ethernet.etherType)
		{
			16w0x800:parse_ipv4;
			16w0x0806:parse_arp;
			default:accept;
		}
	}

    @name("_start") state start 
	{
         transition parse_ethernet;
        }

    @name("_parse_arp") state parse_arp 
	{
         	packet.extract(hdr.arp);
		transition accept;
        }

    @name("_parse_ipv4") state parse_ipv4
	{
		packet.extract(hdr.ipv4);
		transition select(hdr.ipv4.protocol)
		{	8w0x01:parse_icmp;
			default:accept;
		}
	}     	
    @name("_parse_icmp")state parse_icmp
	{
		packet.extract(hdr.icmp);
		transition accept;
	}
}

 

/*************************************************************************

************   C H E C K S U M    V E R I F I C A T I O N   *************

*************************************************************************/
control MyVerifyChecksum(inout headers hdr,inout metadata meta)
{
	apply{
		verify_checksum(true,
	{hdr.ipv4.version,hdr.ipv4.ihl,hdr.ipv4.diffserv,hdr.ipv4.totalLen,hdr.ipv4.identification,
	hdr.ipv4.flags,hdr.ipv4.fragOffset,hdr.ipv4.ttl,hdr.ipv4.protocol,hdr.ipv4.srcAddr,hdr.ipv4.dstAddr},
	hdr.ipv4.hdrChecksum,HashAlgorithm.csum16);
		verify_checksum(true,
        {hdr.icmp.type,hdr.icmp.code,hdr.icmp.identifier, hdr.icmp.sequence_number},
        hdr.icmp.hdrChecksum,HashAlgorithm.csum16);
	}
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action set_nhop(bit<48> dstAddr,bit<9> port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
	hdr.ethernet.dstAddr= dstAddr;
	standard_metadata.egress_spec = port;
	hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
	p4_logger(hdr.ipv4.ttl);
    }

    action send_arp_reply(bit<48> srcMACAddr) {
	hdr.ethernet.dstAddr = hdr.arp.src_mac;
	hdr.ethernet.srcAddr = srcMACAddr;
	hdr.arp.setValid();
	hdr.arp.op_code = 2;
	bit<32> ip_temp = hdr.arp.dst_ip;
	hdr.arp.dst_ip = hdr.arp.src_ip;
	hdr.arp.dst_mac = hdr.arp.src_mac;
	hdr.arp.src_mac = srcMACAddr;
	hdr.arp.src_ip = ip_temp;
	standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    action send_icmp_reply() {
	bit<48> mac_temp = hdr.ethernet.dstAddr;
	hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
	hdr.ethernet.srcAddr = mac_temp;

	bit<32> ip_temp = hdr.ipv4.dstAddr;
	hdr.ipv4.dstAddr = hdr.ipv4.srcAddr;
	hdr.ipv4.srcAddr = ip_temp;

	hdr.icmp.type = 0;
	standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    table ipv4_lpm {
	key = {
		hdr.ipv4.dstAddr:lpm;
	}
	
	actions = {
	    set_nhop;
            drop;
        }
        size = 1024;
	default_action = drop();
    }
	
    table t_handle_ARP {
	key = {
		standard_metadata.ingress_port:exact;
		hdr.arp.dst_ip:exact;
	}
	
	actions = {
	    send_arp_reply;
            drop;
        }
        size = 100;
	default_action = drop();
    }

    table mac_forward {
        key = {
            hdr.ethernet.dstAddr: exact;
        }

        actions = {
            forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    table t_handle_icmp{
	key = {
            hdr.ipv4.dstAddr: exact;
        }
	actions = {
	    send_icmp_reply;
            drop;
        }
    }

    apply{
	if(hdr.arp.isValid())
	{
		if(hdr.arp.op_code == 1)
		{
			if(t_handle_ARP.apply().hit)
			{
				return;
			}
		}
	}
	if(hdr.icmp.isValid())
	{
		if(hdr.icmp.type == 8)
		{
			if(t_handle_icmp.apply().hit)
			{
				return;
			}
			else
			{
				ipv4_lpm.apply();
			}
		}
		else
		{
			ipv4_lpm.apply();
		}
	}
	else
	{
		ipv4_lpm.apply();
	}
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
control MyComputeChecksum(inout headers hdr, inout metadata meta)
{
	apply{
		update_checksum(true,
	{hdr.ipv4.version,hdr.ipv4.ihl,hdr.ipv4.diffserv,hdr.ipv4.totalLen,hdr.ipv4.identification,
	hdr.ipv4.flags,hdr.ipv4.fragOffset,hdr.ipv4.ttl,hdr.ipv4.protocol,hdr.ipv4.srcAddr,hdr.ipv4.dstAddr},
	hdr.ipv4.hdrChecksum,HashAlgorithm.csum16);
		update_checksum(true,
        {hdr.icmp.type,hdr.icmp.code,hdr.icmp.identifier, hdr.icmp.sequence_number},
        hdr.icmp.hdrChecksum,HashAlgorithm.csum16);
	}
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
      packet.emit(hdr.ethernet);
      packet.emit(hdr.ipv4);
      packet.emit(hdr.arp);
      packet.emit(hdr.icmp);
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