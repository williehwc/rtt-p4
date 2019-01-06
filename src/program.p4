/* -*- P4_16 -*- */


#include <core.p4>
#include <v1model.p4>


//use to toggle support for cumulative ACKs
#define MSS_FLAG 

#define TIMESTAMP_BITS 48
#define FLOWID_BITS 128

#ifdef MSS_FLAG
#define MSSID_BITS 96
#endif

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_TCP = 0x6;
const bit<32> MAX_NUM_RTTS = 128;

#ifdef MSS_FLAG
const bit<6>  SYN_FLAG = 6w2;
//const bit<6>  SYN_ACK_FLAG = 6w18;
#endif

const bit<32> TABLE_SIZE = 32w5;

#ifdef MSS_FLAG
const bit<32> MSS_TABLE_SIZE = 32w100; //make sure sufficiently large to limit collisions
#endif

const bit<32> NUM_TABLES = 32w4;
const bit<32> DROP_INDX = NUM_TABLES;
const bit<32> REGISTER_SIZE = TABLE_SIZE * (NUM_TABLES+1); //+1 for drop table
const bit<TIMESTAMP_BITS> LATENCY_THRESHOLD = 0x0000004C4B40; //5 seconds


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


#ifdef MSS_FLAG
/* TCP Options */
/* For now we are assuming static the MSS option is immediately after the
TCP heaer for all SYN packets */
header tcp_mss_option_t{
	bit<8> kind;
	bit<8> len;
	bit<16> mss;
}
#endif

struct metadata {
	bit<FLOWID_BITS> flowID;
	bit<32> hash_key;
	
	bit<32> eACK;
	bit<32> payload_size;

#ifdef MSS_FLAG
	bit<MSSID_BITS> mssID; //separate identifier for MSS table
	bit<32> mssKey;
#endif
}


struct headers {
	ethernet_t   ethernet;
	ipv4_t	   ipv4;
	tcp_t		tcp;
#ifdef MSS_FLAG
	tcp_mss_option_t mss;
#endif
}


/*************************************************************************
*********************** R E G I S T E R S  *****************************
*************************************************************************/

/* register array to store timestamps */
register<bit<TIMESTAMP_BITS>>(REGISTER_SIZE) timestamps;
register<bit<FLOWID_BITS>>(REGISTER_SIZE) keys;

#ifdef MSS_FLAG
register<bit<16>>(MSS_TABLE_SIZE) fourTupleMSS;
#endif

/* register for current RTT register index */
register<bit<32>>(1) current_rtt_index;

/* register/array to store RTTs in the order they are computed */
register<bit<TIMESTAMP_BITS>>(MAX_NUM_RTTS) rtts;
register<bit<32>>(MAX_NUM_RTTS) register_indices_of_rtts;

//register<bit<8>>(REGISTER_SIZE) eACKs;

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
		transition select(hdr.tcp.ctrl){
#ifdef MSS_FLAG
			SYN_FLAG : parse_mss;
//			SYN_ACK_FLAG : parse_mss;
#endif
			default: accept; //everything else including ACKs
		}

	}

#ifdef MSS_FLAG
	state parse_mss {
		packet.extract(hdr.mss);
		transition accept;
	}
#endif

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

	/* calculate payload of tcp packet */
	action set_payload_size(){
		meta.payload_size = ((bit<32>)(hdr.ipv4.totalLen - ((((bit<16>) hdr.ipv4.ihl) + ((bit<16>)hdr.tcp.dataOffset)) * 16w4)));
	}

	/* set expected ACK */
	action set_eACK(){
		meta.eACK = hdr.tcp.seqNo + meta.payload_size;
	}

	/* save metadata tuple */
	action set_flowID(bool isOutgoing){
		if(isOutgoing){
			meta.flowID = hdr.ipv4.srcAddr ++ hdr.ipv4.dstAddr ++ hdr.tcp.srcPort ++ hdr.tcp.dstPort ++ meta.eACK;
		}else{
			meta.flowID = hdr.ipv4.dstAddr ++ hdr.ipv4.srcAddr ++ hdr.tcp.dstPort ++ hdr.tcp.srcPort ++ hdr.tcp.ackNo;
		}
	}
	
	/* hash tuple into key */
	action set_key(){
		hash(meta.hash_key,
			HashAlgorithm.crc32,
			32w0,
			{meta.flowID},
			/*{	
				hdr.ipv4.srcAddr,
				hdr.ipv4.dstAddr,
				hdr.tcp.srcPort,
				hdr.tcp.dstPort,
				hdr.tcp.seqNo
			},*/
			TABLE_SIZE);
		
	}

#ifdef MSS_FLAG	
	/* set the 4 tuple for the maximum segment size storing register */
	action set_mssID(){
		meta.mssID = hdr.ipv4.dstAddr ++ hdr.ipv4.srcAddr ++ hdr.tcp.dstPort ++ hdr.tcp.srcPort;
	}

	/* hash the 4 tuple into an index */
	action set_mssKey(){
		hash(meta.mssKey,
			HashAlgorithm.crc32,
			32w0,
			{meta.mssID},
			MSS_TABLE_SIZE);		
	}
	/* set MSS for SYN packets for each 4 tuple */
	/* ideally we would have perfect hashing or dynamic hash table, because the MSS value is necessary
		for proper operation of the rest of this approach.
	*/
	action push_mss(){
		set_mssID();
		set_mssKey();
		
		fourTupleMSS.write(meta.mssKey, hdr.mss.mss);
	}
#endif

	/* push timestamp into tables with hashed key as index */
	action push_outgoing_timestamp(){
		set_payload_size();
		set_eACK();
		set_flowID(true);
		set_key();

#ifdef MSS_FLAG
		set_mssID();
		set_mssKey();
#endif

		bit<TIMESTAMP_BITS> outgoing_timestamp;

		bit<TIMESTAMP_BITS> time_diff0 = LATENCY_THRESHOLD;
		bit<TIMESTAMP_BITS> time_diff1 = LATENCY_THRESHOLD;
		bit<TIMESTAMP_BITS> time_diff2 = LATENCY_THRESHOLD;
		bit<TIMESTAMP_BITS> time_diff3 = LATENCY_THRESHOLD;

		//hardcoded for 4 tables
		//calculate the time difference between the current time and each of the existing timestamps at that index
		//for each table
		bit<32> offset = 32w0;
		timestamps.read(outgoing_timestamp, meta.hash_key + offset);
		if (outgoing_timestamp != 0) {
			time_diff0 = standard_metadata.ingress_global_timestamp - outgoing_timestamp;
		}
		offset = offset + TABLE_SIZE;
		timestamps.read(outgoing_timestamp, meta.hash_key + offset);
		if (outgoing_timestamp != 0) {
			time_diff1 = standard_metadata.ingress_global_timestamp - outgoing_timestamp;
		}
		offset = offset + TABLE_SIZE;
		timestamps.read(outgoing_timestamp, meta.hash_key + offset);
		if (outgoing_timestamp != 0) {
			time_diff2 = standard_metadata.ingress_global_timestamp - outgoing_timestamp;
		}
		offset = offset + TABLE_SIZE;
		timestamps.read(outgoing_timestamp, meta.hash_key + offset);
		if (outgoing_timestamp != 0) {
			time_diff3 = standard_metadata.ingress_global_timestamp - outgoing_timestamp;
		}

		if(time_diff0 < LATENCY_THRESHOLD){ //no stale packet in table 0
			offset = TABLE_SIZE;
			if(time_diff1 < LATENCY_THRESHOLD){ //no stale packet in table 1
				offset = TABLE_SIZE * 2;
				if(time_diff2 < LATENCY_THRESHOLD){ // no stale packet in table 2
					offset = TABLE_SIZE * 3;
					if(time_diff3 < LATENCY_THRESHOLD){ // no stale packet in table 3
						offset = TABLE_SIZE * DROP_INDX; //essentially a drop
					}
				}
			}
		}else{
			offset = 32w0; //insert into table 0
		}
		

#ifdef MSS_FLAG
		//only allow packets that are full sized (=MSS) to be processed
		bit<16> mss;
		fourTupleMSS.read(mss, meta.mssKey);
		if(meta.payload_size != (bit<32>) mss){
			offset = DROP_INDX;
		}
#endif
		//write to appropriate table at index
		timestamps.write(meta.hash_key+offset, standard_metadata.ingress_global_timestamp);
		keys.write(meta.hash_key+offset, meta.flowID);
	}
	
	/* read timestamp from table and subtract from current time to get rtt*/
	action get_rtt(){
		set_flowID(false);
		set_key();
		
		bit<32> offset = TABLE_SIZE * 4;
		bit<FLOWID_BITS> rflowID;

		bit<TIMESTAMP_BITS> rtt;
		bit<32> rtt_index;
		bit<TIMESTAMP_BITS> outgoing_timestamp;
		
		//update index by going backwards through tables
		keys.read(rflowID, meta.hash_key+TABLE_SIZE*3);
		timestamps.read(outgoing_timestamp, meta.hash_key+TABLE_SIZE*3);
		if(rflowID == meta.flowID && outgoing_timestamp != 0){
			offset = TABLE_SIZE*3;
		}
		keys.read(rflowID, meta.hash_key+TABLE_SIZE*2);
		timestamps.read(outgoing_timestamp, meta.hash_key+TABLE_SIZE*2);
		if(rflowID == meta.flowID && outgoing_timestamp != 0){
			offset = TABLE_SIZE*2;
		}
		keys.read(rflowID, meta.hash_key+TABLE_SIZE);
		timestamps.read(outgoing_timestamp, meta.hash_key+TABLE_SIZE);
		if(rflowID == meta.flowID && outgoing_timestamp != 0){
			offset = TABLE_SIZE;
		}
		keys.read(rflowID, meta.hash_key);
		timestamps.read(outgoing_timestamp, meta.hash_key);
		if(rflowID == meta.flowID && outgoing_timestamp != 0){
			offset = 0;
		}
		
		timestamps.read(outgoing_timestamp, meta.hash_key + offset);
		rtt = standard_metadata.ingress_global_timestamp - outgoing_timestamp;
		
		// For debugging purposes, write RTT to source MAC address if available
		if(offset < TABLE_SIZE*4){
			hdr.ethernet.srcAddr = rtt;
		}else{
			hdr.ethernet.srcAddr = 48w0;
		}

		// Write RTT to rtts register
		current_rtt_index.read(rtt_index, 0);
		rtts.write(rtt_index, rtt);
		register_indices_of_rtts.write(rtt_index, meta.hash_key + offset);
		current_rtt_index.write(0, (rtt_index + 1) % MAX_NUM_RTTS);

		// Set timestamp to 0
		timestamps.write(meta.hash_key + offset, 0);

	}
	
	
	action drop() {
		mark_to_drop();
	}
	

	table tcp_flag_match {
		key = {
			hdr.tcp.ctrl: exact;
		}
		actions = {
			push_outgoing_timestamp;
			get_rtt;
#ifdef MSS_FLAG
			push_mss;
#endif
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
			if(hdr.tcp.ctrl != 4){
				tcp_flag_match.apply();
			}else {
				drop();
			}
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
#ifdef MSS_FLAG
		packet.emit(hdr.mss);
#endif
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
