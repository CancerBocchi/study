control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t std_meta) {
    action broadcast() {
        // 广播到所有端口（除接收端口）
        std_meta.egress_spec = (bit<9>)0x1FF; // 所有端口掩码
        std_meta.mcast_grp = 1; // 启用多播
    }

    apply {
        broadcast();
    }
}
