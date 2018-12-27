/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_TCP = 0x6;

#define TABLE_SIZE 32w100
#define TIMESTAMP_BITS 48
#define TUPLE_BITS 128

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
	macAddr_t dstAddr;
	macAddr_t srcAddr;
	bit<16>   etherType;
}

header ipv4_t {
	bit<4>	version;
	bit<4>	ihl;
	bit<8>	diffserv;
	bit<16>   totalLen;
	bit<16>   identification;
	bit<3>	flags;
	bit<13>   fragOffset;
	bit<8>	ttl;
	bit<8>	protocol;
	bit<16>   hdrChecksum;
	ip4Addr_t srcAddr;
	ip4Addr_t dstAddr;
}

/* TCP Header */
header tcp_t {
	bit<16> srcPort;
	bit<16> dstPort;
	bit<32> seqNo;
	bit<32> ackNo;
	bit<4>  dataOffset;
	bit<3>  res;
	bit<3>  ecn;
	bit<6>  ctrl;
	bit<16> window;
	bit<16> checksum;
	bit<16> urgentPtr;
}

struct tuple_t {
	ip4Addr_t srcAddr;
	ip4Addr_t dstAddr;
	bit<16> srcPort;
	bit<16> dstPort;
	bit<32> seqNo;
}

struct metadata {
	tuple_t tup;
	bit<16> hash_key;
	bit<TIMESTAMP_BITS> outgoing_timestamp;
	bit<TIMESTAMP_BITS> rtt;
}


struct headers {
	ethernet_t   ethernet;
	ipv4_t	   ipv4;
	tcp_t		tcp;
}


/*************************************************************************
*********************** R E G I S T E R S  *****************************
*************************************************************************/

/* register array to store timestamps */
register<bit<TIMESTAMP_BITS>>(TABLE_SIZE) timestamps;
register<bit<TUPLE_BITS>>(TABLE_SIZE) keys;
register<bit<8>>(TABLE_SIZE) eACKs;

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
				out headers hdr,
				inout metadata meta,
				inout standard_metadata_t standard_metadata) {

	state start {
		transition parse_ethernet;
	}

	state parse_ethernet {
		packet.extract(hdr.ethernet);
		transition select(hdr.ethernet.etherType) {
			TYPE_IPV4: parse_ipv4;
			default: accept;
		}
	}

	state parse_ipv4 {
		packet.extract(hdr.ipv4);
		/* check to see if tcp packet */
		transition select(hdr.ipv4.protocol) {
			TYPE_TCP: parse_tcp;
			default: accept;
		}
	}

	state parse_tcp {
		packet.extract(hdr.tcp);
		transition accept;
	}

}

/*************************************************************************
************   C H E C K S U M	V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
	apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/


control MyIngress(inout headers hdr,
				  inout metadata meta,
				  inout standard_metadata_t standard_metadata) {

	/* save metadata tuple */
	action set_tuple(bool isOutgoing){
		if(isOutgoing){
			meta.tup.srcAddr = hdr.ipv4.srcAddr;
			meta.tup.dstAddr = hdr.ipv4.dstAddr;
			meta.tup.srcPort = hdr.tcp.srcPort;
			meta.tup.dstPort = hdr.tcp.dstPort;
		}else{
			meta.tup.srcAddr = hdr.ipv4.dstAddr;
			meta.tup.dstAddr = hdr.ipv4.srcAddr;
			meta.tup.srcPort = hdr.tcp.dstPort;
			meta.tup.dstPort = hdr.tcp.srcPort;
		}
		meta.tup.seqNo = hdr.tcp.seqNo;
	}
	
	/* hash tuple into key */
	action set_key(){
		hash(meta.hash_key,
			HashAlgorithm.crc32,
			32w0,
			meta.tup,
			/*{	
				hdr.ipv4.srcAddr,
				hdr.ipv4.dstAddr,
				hdr.tcp.srcPort,
				hdr.tcp.dstPort,
				hdr.tcp.seqNo
			},*/
			TABLE_SIZE);
		
	}
	
	
	/* push timestamp into table with hashed key as index */
	action push_outgoing_timestamp(){	
		set_tuple(true);
		set_key();
		timestamps.write((bit<32>)meta.hash_key, standard_metadata.ingress_global_timestamp);
		keys.write((bit<32>)meta.hash_key, meta.tup);
	}
	
	/* read timestamp from table and subtract from current time to get rtt*/
	action get_rtt(){
		set_tuple(false);
		set_key();
		timestamps.read(meta.outgoing_timestamp, (bit<32>) meta.hash_key);
		meta.rtt = standard_metadata.ingress_global_timestamp - meta.outgoing_timestamp;
		// Write RTT to source MAC address
		hdr.ethernet.srcAddr = meta.rtt;
	}
	
	
	action drop() {
		mark_to_drop();
	}
	
	/* write timestamp to src mac address */
	action write_timestamp(){
		hdr.ethernet.srcAddr = standard_metadata.ingress_global_timestamp;
	}

	table tcp_flag_match {
		key = {
			hdr.tcp.ctrl: exact;
		}
		actions = {
			push_outgoing_timestamp;
			get_rtt;
			NoAction;
		}
		size = 2;
		default_action = push_outgoing_timestamp();
	}
	
	action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
		standard_metadata.egress_spec = port;
		hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
		hdr.ethernet.dstAddr = dstAddr;
		hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
	}

	table ipv4_lpm {
		key = {
			hdr.ipv4.dstAddr: lpm;
		}
		actions = {
			ipv4_forward;
			drop;
			NoAction;
		}
		size = 1024;
		default_action = drop();
	}
	
	apply {
		if (hdr.ipv4.isValid()) {
			ipv4_lpm.apply();
		}
		if (hdr.tcp.isValid()) {
			tcp_flag_match.apply();
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
*************   C H E C K S U M	C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
	 apply {
	update_checksum(
		hdr.ipv4.isValid(),
			{ hdr.ipv4.version,
		  hdr.ipv4.ihl,
			  hdr.ipv4.diffserv,
			  hdr.ipv4.totalLen,
			  hdr.ipv4.identification,
			  hdr.ipv4.flags,
			  hdr.ipv4.fragOffset,
			  hdr.ipv4.ttl,
			  hdr.ipv4.protocol,
			  hdr.ipv4.srcAddr,
			  hdr.ipv4.dstAddr },
			hdr.ipv4.hdrChecksum,
			HashAlgorithm.csum16);
	}
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
	apply {
		packet.emit(hdr.ethernet);
		packet.emit(hdr.ipv4);
		packet.emit(hdr.tcp);
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
