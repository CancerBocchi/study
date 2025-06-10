header ethernet_h {
	bit<48>    dst;
	bit<48>    src;
	bit<16>    etherType;
}
header arp_h {
	bit<16>      h_type;
	bit<16>      p_type;
	bit<8>       h_len;
	bit<8>       p_len;
	bit<16>      op_code;
	bit<48>      src_mac;
	bit<32>      src_ip;
	bit<48>      dst_mac;
	bit<32>      dst_ip;
}
header ipv4_h {
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

header udp_h {
	bit<16>    srcPort;
	bit<16>    dstPort;
	bit<16>    len;
	bit<16>    checksum;
}
header icmp_h {
    bit<8>    type;
    bit<8>    code;
    bit<16>   hdrChecksum;
    bit<16>   identifier;
    bit<16>   sequence_number;
    bit<64>   timestamp;
}
struct myheaders {
	ethernet_h		ethernet;
	arp_h           arp;
	ipv4_h 			ipv4;
	udp_h 			udp;
	icmp_h          icmp;
}

parser MyParser(packet_in packet,
	out myheaders hdr,
	inout metadata meta,
	inout standard_metadata_t standard_metadata) 
{

}
header ethernet_h {
	bit<48>    dst;
	bit<48>    src;
	bit<16>    etherType;
}
header arp_h {
	bit<16>      h_type;
	bit<16>      p_type;
	bit<8>       h_len;
	bit<8>       p_len;
	bit<16>      op_code;
	bit<48>      src_mac;
	bit<32>      src_ip;
	bit<48>      dst_mac;
	bit<32>      dst_ip;
}
header ipv4_h {
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
header udp_h {
	bit<16>    srcPort;
	bit<16>    dstPort;
	bit<16>    len;
	bit<16>    checksum;
}
header icmp_h {
    bit<8>    type;
    bit<8>    code;
    bit<16>   hdrChecksum;
    bit<16>   identifier;
    bit<16>   sequence_number;
    bit<64>   timestamp;
}
struct myheaders {
	ethernet_h		ethernet;
	arp_h           arp;
	ipv4_h 			ipv4;
	udp_h 			udp;
	icmp_h          icmp;
}

parser MyParser(packet_in packet,
	out myheaders hdr,
	inout metadata meta,
	inout standard_metadata_t standard_metadata) 
{
	state start{
		transition parse_ethernet;
	}

	state parse_ethernet {
	    packet.extract(hdr.ethernet);
		transition select(hdr.ethernet.ethertype){
			0x800: parse_ipv4;
			0x0806: parse_arp;
			defualt:accept;
		}
	}

	state parse_ipv4{
		packet.extract(hdr.ipv4);
		transition select(hdr.ipv4.protocol){
			0x11: parse_udp;
			0x01: parse_icmp;
			defualt: accept;
		}
	}

	state parse_arp{
		packet.extract(hdr.arp);
	    transition accept;
	}

	state parse_udp{
		packet.extract(hdr.udp);
	    transition accept;
	}

	state parse_icmp{
		packet.extract(hdr.icmp);
		transition accept;
	}
}


