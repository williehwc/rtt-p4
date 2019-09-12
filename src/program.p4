/* -*- P4_16 -*- */
/* P4 program for measuring round trip time */
/* Javed Aman and Willie Chang */
/* Princeton University Computer Science Department */

#include <core.p4>
#include <v1model.p4>

/* size of timestamp (milliseconds) */
#define TIMESTAMP_BITS 48
/* size of flow_id */
#define FLOWID_BITS 128

/*use to toggle support for deterministic subsampling */
#define SUBSAMPLE_FLAG

/* use to toggle support for cumulative ACKs */
#define MSS_FLAG 

/* define the number of tables MULTI_TABLE == 2 */
#define MULTI_TABLE 2

/* if using UDP to send stat packet */
#define STAT_PACKET

/* if tracking MSS */
#ifdef MSS_FLAG
/* size of MSS */
#define MSSID_BITS 96
#endif

/* ipv4 type header */
const bit<16> TYPE_IPV4 = 0x800;
/* tcp type header */
const bit<8> TYPE_TCP = 0x6;

/* maximum number of rtts to track */
const bit<32> MAX_NUM_RTTS = 1024;

/* syn flag header */
#ifdef MSS_FLAG
const bit<1>  SYN_FLAG = 1w1;
#endif

/* number of timestamps to tables */
const bit<32> TABLE_SIZE = 120;

/* table to store MSS for flows*/
#ifdef MSS_FLAG
const bit<32> MSS_TABLE_SIZE = 32w1000;
#endif

/* set number of hash tables */
#ifdef MULTI_TABLE
// a little unclear, would prefer 32w{MULTI_TABLE}
const bit<32> NUM_TABLES = (bit<32>) MULTI_TABLE;
#else
const bit<32> NUM_TABLES = 32w1;
#endif

/* handle drop index */
const bit<32> DROP_INDX = NUM_TABLES;
/* calculate size of register of hash tables */
const bit<32> REGISTER_SIZE = TABLE_SIZE * (NUM_TABLES+1); //+1 for drop table

/* default mss */
const bit<32> DEFAULT_MSS = 32w1460;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

/* Ethernet header */
header ethernet_t {
	macAddr_t dstAddr;
	macAddr_t srcAddr;
	bit<16>   etherType;
}

/* ipv4 header */
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
	bit<1>  urg;
	bit<1>  ack;
	bit<1>  psh;
	bit<1>  rst;
	bit<1>  syn;
	bit<1>  fin;
	bit<16> window;
	bit<16> checksum;
	bit<16> urgentPtr;
}

#ifdef STAT_PACKET
header udp_pay_t {
    //measurement report, including IP+UDP header
    //IP
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ip4Addr_t src_addr;
    ip4Addr_t dst_addr;
	//UDP
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
	bit<FLOWID_BITS> flowID;
	bit<TIMESTAMP_BITS> rtt;
}
#endif

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
	/* flow id */
	bit<FLOWID_BITS> flowID;
	/* hash of flow */
	bit<32> hash_key;
	/* expected ack hash */
	bit<32> eACK;
	/* size of packet payload */
	bit<32> payload_size;

	#ifdef MSS_FLAG
	//separate identifier for MSS table
	bit<MSSID_BITS> mssID;
	bit<32> mss_key;
	#endif

	#ifdef SUBSAMPLE_FLAG
	//p4-16 runtime doesn't allow boolean values in header/metadata
	/* flag if packet is being sampled */
	bit<1> sampled;
	#endif
}


struct headers {
	ethernet_t   ethernet;
	ipv4_t	   ipv4;
	tcp_t		tcp;
	#ifdef STAT_PACKET
	udp_pay_t stat;
	#endif
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
/* store mss of packet flows in table */
register<bit<16>>(MSS_TABLE_SIZE) four_tuple_mss_table;
#endif

/* register for current RTT register index */
register<bit<32>>(1) current_rtt_index;

/* register/array to store RTTs in the order they are computed */
register<bit<TIMESTAMP_BITS>>(MAX_NUM_RTTS) rtts;
register<bit<32>>(MAX_NUM_RTTS) register_indices_of_rtts;
register<bit<32>>(MAX_NUM_RTTS) src_ips_of_rtts;
register<bit<32>>(MAX_NUM_RTTS) dst_ips_of_rtts;
register<bit<16>>(MAX_NUM_RTTS) src_ports_of_rtts;
register<bit<16>>(MAX_NUM_RTTS) dst_ports_of_rtts;
register<bit<32>>(MAX_NUM_RTTS) seq_nos_of_rtts;
register<bit<32>>(MAX_NUM_RTTS) ack_nos_of_rtts;

/* registers for tunable parameters */
register<bit<TIMESTAMP_BITS>>(1) latency_threshold;


#ifdef SUBSAMPLE_FLAG
//0% means all packets will be sampled
register<bit<16>>(1) filter_percent;
#endif


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

	/* parse ethernet header */
	state parse_ethernet {
		packet.extract(hdr.ethernet);
		transition select(hdr.ethernet.etherType) {
			TYPE_IPV4: parse_ipv4;
			#ifdef STAT_PACKET
			0x0000 : parse_stat;
			#endif
			default: accept;
		}
	}

	state parse_stat{
		packet.extract(hdr.stat);
		transition parse_ipv4;
	}
	/* parse ipv4 header */
	state parse_ipv4 {
		packet.extract(hdr.ipv4);
		/* check to see if tcp packet */
		transition select(hdr.ipv4.protocol) {
			TYPE_TCP: parse_tcp;
			default: accept;
		}
	}

	/* parse tcp header */
	state parse_tcp {
		packet.extract(hdr.tcp);
		transition select(hdr.tcp.syn){
			#ifdef MSS_FLAG
				SYN_FLAG : parse_mss;
			#endif
			//everything else including ACKs
			default: accept;
		}

	}

	#ifdef MSS_FLAG
	/* parse static MSS option*/
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
			TABLE_SIZE);
		
	}

	#ifdef MSS_FLAG	
	/* set the 4 tuple for the maximum segment size storing register */
	action set_mssID(){
		meta.mssID = hdr.ipv4.dstAddr ++ hdr.ipv4.srcAddr ++ hdr.tcp.dstPort ++ hdr.tcp.srcPort;
	}

	/* hash the 4 tuple into an index */
	action set_mss_key(){
		hash(meta.mss_key,
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
		set_mss_key();
		
		four_tuple_mss_table.write(meta.mss_key, hdr.mss.mss);
	}
	#endif


	#ifdef SUBSAMPLE_FLAG
	/* determine if a packet should be sampled based on the crc32 hash */
	action to_be_sampled(){
		bit<16> sample_key = 16w100;
		hash(sample_key,
			HashAlgorithm.crc16,
			16w0,
			{meta.flowID},
			16w100);
		
		bit<16> fp = 16w0;
		filter_percent.read(fp, 0);

		if(sample_key >= fp){
			meta.sampled = 1w1; 
		}else{
			meta.sampled = 1w0;
		}

	}
	#endif
	
	#ifdef STAT_PACKET
	action set_udp_payload(bit<TIMESTAMP_BITS> rtt) {
        hdr.stat.setValid();
        //ip
        hdr.stat.version=4;
        hdr.stat.ihl=5;
        hdr.stat.diffserv=0;
        hdr.stat.totalLen=hdr.ipv4.totalLen + 20 + 8 + 8;//+ipv4 + udp + payload
        hdr.stat.ttl=64;
        hdr.stat.protocol=17;
        hdr.stat.src_addr=0x0a000001;
        hdr.stat.src_addr=0x0a000002;
		hdr.stat.srcPort = hdr.tcp.srcPort;
		hdr.stat.dstPort = hdr.tcp.dstPort;
		hdr.stat.length = 8 + FLOWID_BITS + TIMESTAMP_BITS;
		hdr.stat.checksum = 16w0;
		hdr.stat.flowID = meta.flowID;
		hdr.stat.rtt = rtt;
		
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
		set_mss_key();
		#endif

		bit<TIMESTAMP_BITS> outgoing_timestamp;
		bit<TIMESTAMP_BITS> lt;

		latency_threshold.read(lt, 0);

		//default is one table
		bit<TIMESTAMP_BITS> time_diff0 = lt;

		#if MULTI_TABLE > 1
		bit<TIMESTAMP_BITS> time_diff1 = lt;
		#endif

		//hardcoded for up to 4 tables
		//calculate the time difference between the current time and each of the existing timestamps at that index
		//for each table
		bit<32> offset = 32w0;
		timestamps.read(outgoing_timestamp, meta.hash_key + offset);
		if (outgoing_timestamp != 0) {
			time_diff0 = standard_metadata.ingress_global_timestamp - outgoing_timestamp;
		}

		#if MULTI_TABLE > 1
		offset = TABLE_SIZE;
		timestamps.read(outgoing_timestamp, meta.hash_key + offset);
		if (outgoing_timestamp != 0) {
			time_diff1 = standard_metadata.ingress_global_timestamp - outgoing_timestamp;
		}
		#endif

		if(time_diff0 < lt){ //no stale packet in table 1
			offset = TABLE_SIZE;
			#if MULTI_TABLE > 1
			if(time_diff1 < lt){ //no stale packet in table 2
				offset = TABLE_SIZE * 2;
			}
			#endif //MULTI_TABLE > 1
		}else{
			offset = 32w0; //insert into table 1
		}
		
		#ifdef MSS_FLAG
		//only allow packets that are full sized (=MSS) to be processed
		bit<16> mss;
		four_tuple_mss_table.read(mss, meta.mss_key);
		if((mss != 16w0 && meta.payload_size != (bit<32>) mss) || meta.payload_size != DEFAULT_MSS){
			offset = TABLE_SIZE * DROP_INDX;
		}
		#endif


		#ifdef SUBSAMPLE_FLAG
		to_be_sampled();
		if(meta.sampled == 1w0){
			offset = TABLE_SIZE * DROP_INDX;
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
		
		bit<32> offset = TABLE_SIZE * DROP_INDX;
		bit<FLOWID_BITS> rflowID;

		bit<TIMESTAMP_BITS> rtt;
		bit<32> rtt_index;
		bit<TIMESTAMP_BITS> outgoing_timestamp;
		
		//update index by going backwards through tables

		#if MULTI_TABLE > 1
		keys.read(rflowID, meta.hash_key+TABLE_SIZE);
		timestamps.read(outgoing_timestamp, meta.hash_key+TABLE_SIZE);
		if(rflowID == meta.flowID && outgoing_timestamp != 0){
			offset = TABLE_SIZE;
		}
		#endif

		//default is one table
		keys.read(rflowID, meta.hash_key);
		timestamps.read(outgoing_timestamp, meta.hash_key);
		if(rflowID == meta.flowID && outgoing_timestamp != 0){
			offset = 0;
		}
		
		timestamps.read(outgoing_timestamp, meta.hash_key + offset);
		rtt = standard_metadata.ingress_global_timestamp - outgoing_timestamp;



		#ifdef SUBSAMPLE_FLAG
		to_be_sampled();
		if(meta.sampled == 1w0){ //false
			offset = TABLE_SIZE * DROP_INDX;
		}
		#endif
		
		// For debugging purposes, write RTT to source MAC address if available
		if(offset < TABLE_SIZE*DROP_INDX){
			hdr.ethernet.srcAddr = rtt;
		}else{
			hdr.ethernet.srcAddr = 48w0;
		}

		// Write RTT to rtts register
		current_rtt_index.read(rtt_index, 0);
		rtts.write(rtt_index, rtt);
		register_indices_of_rtts.write(rtt_index, meta.hash_key + offset);
		src_ips_of_rtts.write(rtt_index, hdr.ipv4.srcAddr);
		dst_ips_of_rtts.write(rtt_index, hdr.ipv4.dstAddr);
		src_ports_of_rtts.write(rtt_index, hdr.tcp.srcPort);
		dst_ports_of_rtts.write(rtt_index, hdr.tcp.dstPort);
		seq_nos_of_rtts.write(rtt_index, hdr.tcp.seqNo);
		ack_nos_of_rtts.write(rtt_index, hdr.tcp.ackNo);
		current_rtt_index.write(0, (rtt_index + 1) % MAX_NUM_RTTS);

		// Set timestamp to 0
		timestamps.write(meta.hash_key + offset, 0);
		
		#ifdef STAT_PACKET
		set_udp_payload(rtt);
		#endif
		

	}
	
	/* drop irrelevant packets */
	action drop() {
		mark_to_drop();
	}
	
	/* handle ACK packets */
	action handle_ack(){
		push_outgoing_timestamp();
		get_rtt();
	}

	table tcp_flag_syn_match {
		key = {
			hdr.tcp.syn: exact;
		}
		actions = {
			#ifdef MSS_FLAG
			push_mss;
			#endif
			NoAction;
		}
		size = 2;
		default_action = NoAction();
	}

	table tcp_flag_ack_match {
		key = {
			hdr.tcp.ack: exact;
		}
		actions = {
			push_outgoing_timestamp;
			handle_ack;
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
			if(hdr.tcp.rst != 1w1){
				tcp_flag_syn_match.apply();
				tcp_flag_ack_match.apply();
			} else {
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
		#ifdef STAT_PACKET
		packet.emit(hdr.stat);
		#else
		packet.emit(hdr.tcp);
		#ifdef MSS_FLAG
		packet.emit(hdr.mss);
		#endif //MSS_FLAG
		#endif //STAT_PACKET
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
