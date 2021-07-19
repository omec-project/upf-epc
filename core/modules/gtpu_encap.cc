/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2019 Intel Corporation
 */
/* for gtpu_encap decls */
#include "gtpu_encap.h"
/* for rte_zmalloc() */
#include <rte_malloc.h>
/* for IPVERSION */
#include <netinet/ip.h>
/* for be32_t */
#include "utils/endian.h"
/* for ToIpv4Address() */
#include "utils/ip.h"
/* for udp header */
#include "utils/udp.h"
/* for ethernet header */
#include "utils/ether.h"
/* for gtp header */
#include "utils/gtp.h"
/* for GetDesc() */
#include "utils/format.h"
#include <rte_jhash.h>
/*----------------------------------------------------------------------------------*/
using bess::utils::be16_t;
using bess::utils::be32_t;
using bess::utils::Ethernet;
using bess::utils::Gtpv1;
using bess::utils::Gtpv1PDUSessExt;
using bess::utils::Gtpv1SeqPDUExt;
using bess::utils::Ipv4;
using bess::utils::ToIpv4Address;
using bess::utils::Udp;

enum { DEFAULT_GATE = 0, FORWARD_GATE };
/*----------------------------------------------------------------------------------*/
// Template for generating UDP packets without data
struct [[gnu::packed]] PacketTemplate {
  Ipv4 iph;
  Udp udph;
  Gtpv1 gtph;
  Gtpv1SeqPDUExt speh;
  Gtpv1PDUSessExt psch;

  PacketTemplate() {
    psch.qfi = 0;  // to fill in
    psch.spare2 = 0;
    psch.spare1 = 0;
    psch.pdu_type = 0;  // to fill in
    psch.hlen = psch.header_length();
    speh.ext = psch.type();
    speh.npdu = 0;
    speh.seqnum = (be16_t)0;
    gtph.version = GTPU_VERSION;
    gtph.pt = GTP_PROTOCOL_TYPE_GTP;
    gtph.spare = 0;
    gtph.ex = 0;  // conditionally set this
    gtph.seq = 0;
    gtph.pdn = 0;
    gtph.type = GTP_GPDU;
    gtph.length = (be16_t)0;  // to fill in
    gtph.teid = (be32_t)0;    // to fill in
    udph.src_port = (be16_t)UDP_PORT_GTPU;
    udph.dst_port = (be16_t)UDP_PORT_GTPU;
    udph.length = (be16_t)0;  // to fill in
    /* calculated by L4Checksum module in line */
    udph.checksum = 0;
    iph.version = IPVERSION;
    iph.header_length = (sizeof(Ipv4) >> 2);
    iph.type_of_service = 0;
    iph.length = (be16_t)0;  // to fill in
    iph.id = (be16_t)0x513;
    iph.fragment_offset = (be16_t)0;
    iph.ttl = 64;
    iph.protocol = IPPROTO_UDP;
    /* calculated by IPChecksum module in line */
    iph.checksum = 0;
    iph.src = (be32_t)0;  // to fill in
    iph.dst = (be32_t)0;  // to fill in
  }
};
static PacketTemplate outer_ip_template;
/*----------------------------------------------------------------------------------*/
void GtpuEncap::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  int cnt = batch->cnt();

  for (int i = 0; i < cnt; i++) {
    bess::Packet *p = batch->pkts()[i];

    /* check attributes' values now */
    uint8_t at_pdu_type;
    bess::metadata::mt_offset_t off = attr_offset(pdu_type_attr);
    at_pdu_type = get_attr_with_offset<uint8_t>(off, p);

    uint8_t at_qfi;
    off = attr_offset(qfi_attr);
    at_qfi = get_attr_with_offset<uint8_t>(off, p);

    uint32_t at_tout_sip;
    off = attr_offset(tout_sip_attr);
    at_tout_sip = get_attr_with_offset<uint32_t>(off, p);

    uint32_t at_tout_dip;
    off = attr_offset(tout_dip_attr);
    at_tout_dip = get_attr_with_offset<uint32_t>(off, p);

    uint32_t at_tout_teid;
    off = attr_offset(tout_teid);
    at_tout_teid = get_attr_with_offset<uint32_t>(off, p);

    uint16_t at_tout_uport;
    off = attr_offset(tout_uport);
    at_tout_uport = get_attr_with_offset<uint16_t>(off, p);

    /* checking values now */
    DLOG(INFO) << "pdu type: " << static_cast<uint16_t>(at_pdu_type)
               << ", tunnel qfi: " << at_qfi
               << ", tunnel out sip: " << at_tout_sip
               << ", tunnel out dip: " << at_tout_dip
               << ", tunnel out teid: " << at_tout_teid
               << ", tunnel out udp port: " << at_tout_uport << std::endl;

    uint16_t pkt_len = p->total_len() - sizeof(Ethernet);
    Ethernet *eth = p->head_data<Ethernet *>();

    /* pre-allocate space for encaped header(s) */
    char *new_p = static_cast<char *>(p->prepend(encap_size));
    if (new_p == NULL) {
      /* failed to prepend header space for encaped packet */
      EmitPacket(ctx, p, DEFAULT_GATE);
      DLOG(INFO) << "prepend() failed!" << std::endl;
      continue;
    }

    /* setting Ethernet header */
    memcpy(new_p, eth, sizeof(Ethernet));

    /* get pointers to header offsets */
    Ipv4 *iph = (Ipv4 *)(new_p + sizeof(Ethernet));

    Udp *udph = (Udp *)(new_p + sizeof(Ethernet) + sizeof(Ipv4));

    Gtpv1 *gtph = (Gtpv1 *)((uint8_t *)iph + offsetof(PacketTemplate, gtph));

    Gtpv1PDUSessExt *psch =
        (Gtpv1PDUSessExt *)((uint8_t *)iph + offsetof(PacketTemplate, psch));

    /* copying template content */
    bess::utils::Copy(iph, &outer_ip_template, encap_size);

    /* setting gtp psc extension header*/
    if (add_psc) {
      gtph->ex = 1;
      psch->qfi = at_qfi;
      psch->pdu_type = at_pdu_type;
    }

    /* calculate lengths */
    uint16_t gtplen =
        pkt_len + encap_size - sizeof(Gtpv1) - sizeof(Udp) - sizeof(Ipv4);
    uint16_t udplen = gtplen + sizeof(Gtpv1) + sizeof(Udp);
    uint16_t iplen = udplen + sizeof(Ipv4);

    /* setting gtpu header */
    gtph->length = (be16_t)(gtplen);
    gtph->teid = (be32_t)(at_tout_teid);

    /* setting outer UDP header */
    udph->length = (be16_t)(udplen);
    udph->src_port = udph->dst_port = (be16_t)(at_tout_uport);

    /* setting outer IP header */
    iph->length = (be16_t)(iplen);
    iph->src = (be32_t)(at_tout_sip);
    iph->dst = (be32_t)(at_tout_dip);

    EmitPacket(ctx, p, FORWARD_GATE);
  }
}
/*----------------------------------------------------------------------------------*/
CommandResponse GtpuEncap::Init(const bess::pb::GtpuEncapArg &arg) {
  add_psc = arg.add_psc();
  if (add_psc)
    encap_size = sizeof(outer_ip_template);
  else
    encap_size = sizeof(outer_ip_template) - sizeof(Gtpv1SeqPDUExt) -
                 sizeof(Gtpv1SeqPDUExt);

  using AccessMode = bess::metadata::Attribute::AccessMode;
  pdu_type_attr = AddMetadataAttr("action", sizeof(uint8_t), AccessMode::kRead);
  DLOG(INFO) << "tout_sip_attr: " << tout_sip_attr << std::endl;
  tout_sip_attr = AddMetadataAttr("tunnel_out_src_ip4addr", sizeof(uint32_t),
                                  AccessMode::kRead);
  DLOG(INFO) << "tout_sip_attr: " << tout_sip_attr << std::endl;
  tout_dip_attr = AddMetadataAttr("tunnel_out_dst_ip4addr", sizeof(uint32_t),
                                  AccessMode::kRead);
  DLOG(INFO) << "tout_dip_attr: " << tout_dip_attr << std::endl;
  tout_teid =
      AddMetadataAttr("tunnel_out_teid", sizeof(uint32_t), AccessMode::kRead);
  DLOG(INFO) << "tout_teid: " << tout_teid << std::endl;
  tout_uport = AddMetadataAttr("tunnel_out_udp_port", sizeof(uint16_t),
                               AccessMode::kRead);
  DLOG(INFO) << "tout_uport: " << tout_uport << std::endl;
  qfi_attr = AddMetadataAttr("qfi", sizeof(uint8_t), AccessMode::kRead);
  DLOG(INFO) << "qfi_attr: " << qfi_attr << std::endl;

  return CommandSuccess();
}
/*----------------------------------------------------------------------------------*/
ADD_MODULE(GtpuEncap, "gtpu_encap", "first version of gtpu encap module")
