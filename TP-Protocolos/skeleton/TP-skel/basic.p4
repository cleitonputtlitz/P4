/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define MAX_HOPS 10
#define MTU 1500
#define SIZE_INT_PAI 5
#define SIZE_INT_FILHO 13
#define SIZE_NORMAL_PKT 54 //14 + 20 + 20


const bit<16> TYPE_IPV4    = 0x800;
const bit<16> TYPE_INT_PAI = 0x1212;

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
} //14 bytes

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
} //20 bytes

//int_pai_t irá armazenar a quantidade de int_filho adicionados
header int_pai_t {
    bit<32> Quantidade_Filhos;
    bit<8> Estouro_MTU;
}

//int_filho irá armazenar os dados coletados de cada switch
header int_filho_t {
    bit<32> Id_switch;
    bit<9>  Porta_Entrada;
    bit<9>  Porta_Saida;
    bit<48> Timestamp;
    bit<6>  Padding;
}

struct metadata {
    //Qtd_Filhos será usado no parser para controlar a quantidade de int_filhos incluídos do pacote
    bit<32> Quantidade_Filhos;
    bit<1>  isEndHost;
    bit<32> packet_size;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    //necessário adicionar as novas estruturas aqui
    int_pai_t   	  int_pai;
    int_filho_t[MAX_HOPS] int_filho;
}

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

//O parse_ethernet será alterado para fazer a transição para o parse_ipv4 ou para o parse_int_pai,
//considerando o que estiver presente no campo etherType
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4:    parse_ipv4;
            TYPE_INT_PAI: parse_int_pai;
            default: accept;
        }
    }

    state parse_int_pai {
        packet.extract(hdr.int_pai);
        meta.Quantidade_Filhos = hdr.int_pai.Quantidade_Filhos;
        transition select(hdr.int_pai.Quantidade_Filhos) {
            0: parse_ipv4;
            default: parse_int_filho;
        }
    }

    state parse_int_filho {
    	//
        packet.extract(hdr.int_filho.next);
        meta.Quantidade_Filhos = meta.Quantidade_Filhos -1;
        //faz uma nova transição para o parse_int_filho enquanto houver int_filho para ser removido
        transition select(meta.Quantidade_Filhos) {
            0: parse_ipv4;
            default: parse_int_filho;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
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
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port, bit<1> isEndHost) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        meta.isEndHost = isEndHost;
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
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    //
    action add_int_pai() {
	     hdr.int_pai.setValid();
	     hdr.int_pai.Quantidade_Filhos = 0;
	     hdr.ethernet.etherType = TYPE_INT_PAI;
    }

    //
    action add_int_filho(bit<32> swid) {
        hdr.int_filho.push_front(1);
        hdr.int_filho[0].setValid();
        hdr.int_filho[0].Id_switch      = swid;
        hdr.int_filho[0].Porta_Entrada  = standard_metadata.ingress_port;
        hdr.int_filho[0].Porta_Saida    = standard_metadata.egress_port;
        hdr.int_filho[0].Timestamp      = (bit <48>) standard_metadata.ingress_global_timestamp;
        hdr.int_filho[0].Padding        = 0;
    }

    //
    table int_filho {
        actions = {
            add_int_filho;
            NoAction;
        }
        default_action = NoAction();
    }

    apply {

    	if (hdr.ipv4.isValid()) {

          if(standard_metadata.instance_type == 0) {

        	    if(!hdr.int_pai.isValid()){
                if(standard_metadata.packet_length + SIZE_INT_PAI < MTU) {
                    add_int_pai();
                }
        	    }

              if(hdr.int_pai.isValid()){
                  if(standard_metadata.packet_length + SIZE_INT_FILHO <= MTU) {

                      hdr.int_pai.Quantidade_Filhos = hdr.int_pai.Quantidade_Filhos + 1;
                      int_filho.apply();

                      if(hdr.int_pai.Quantidade_Filhos == 1) {
                          hdr.int_filho[0].Padding = 1;
                      }
                  }

                  if(meta.isEndHost == 1) {
                      //clonar o pacote
                      //CloneType {I2E /*ingress*/, E2E/*egress*/}
                      //standard_metadata instance_type field pode ser usado para distinguir os pacotes originais do clone
                      //Packet is forwarded according to the mirroring_add command

                      clone(CloneType.E2E, 500);
                      //Remover o INT do pacote original. Remover o payload do clone
                      //https://github.com/jafingerhut/p4-guide/blob/master/v1model-special-ops/README-p414.md

                    }

              }
          } else {
            //Remover o payload do clone
            //calcular o tamanho do pacote (Eth+int_pai+int_filhos+ipv4+tcp)
            meta.packet_size = SIZE_NORMAL_PKT + SIZE_INT_PAI + (SIZE_INT_FILHO * hdr.int_pai.Quantidade_Filhos);
            truncate(meta.packet_size);

          }
      }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
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
        //
        packet.emit(hdr.int_pai);
        packet.emit(hdr.int_filho);
        packet.emit(hdr.ipv4);
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
