// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2020 Intel Corporation

package main

import (
	"log"
	"net"

	"github.com/wmnsk/go-pfcp/ie"
)

type pdr struct {
	srcIface     uint8
	tunnelIP4Dst uint32
	tunnelTEID   uint32
	srcIP        uint32
	dstIP        uint32
	srcPort      uint16
	dstPort      uint16
	proto        uint8

	srcIfaceMask     uint8
	tunnelIP4DstMask uint32
	tunnelTEIDMask   uint32
	srcIPMask        uint32
	dstIPMask        uint32
	srcPortMask      uint16
	dstPortMask      uint16
	protoMask        uint8

	precedence uint32
	pdrID      uint32
	fseID      uint64
	fseidIP    uint32
	ctrID      uint32
	farID      uint32
	qerID      uint32
	qci        uint32
	//schedulingPriority uint32 will be used when we add priority for p4 upf.
	needDecap   uint8
	allocIPFlag bool
}

func needAllocIP(ueIPaddr *ie.UEIPAddressFields) bool {
	if has2ndBit(ueIPaddr.Flags) && !has5thBit(ueIPaddr.Flags) {
		return false
	}
	return true
}

func (p *pdr) printPDR() {
	log.Println("------------------ PDR ---------------------")
	log.Println("Src Iface:", p.srcIface)
	log.Println("tunnelIP4Dst:", int2ip(p.tunnelIP4Dst))
	log.Println("tunnelTEID:", p.tunnelTEID)
	log.Println("srcIP:", int2ip(p.srcIP))
	log.Println("dstIP:", int2ip(p.dstIP))
	log.Println("srcPort:", p.srcPort)
	log.Println("dstPort:", p.dstPort)
	log.Println("proto:", p.proto)
	log.Println("Src Iface Mask:", p.srcIfaceMask)
	log.Println("tunnelIP4Dst Mask:", int2ip(p.tunnelIP4DstMask))
	log.Println("tunnelTEIDMask Mask:", p.tunnelTEIDMask)
	log.Println("srcIP Mask:", int2ip(p.srcIPMask))
	log.Println("dstIP Mask:", int2ip(p.dstIPMask))
	log.Println("srcPort Mask:", p.srcPortMask)
	log.Println("dstPort Mask:", p.dstPortMask)
	log.Println("proto Mask:", p.protoMask)
	log.Println("pdrID:", p.pdrID)
	log.Println("fseID", p.fseID)
	log.Println("fseidIP", p.fseidIP)
	log.Println("ctrID:", p.ctrID)
	log.Println("farID:", p.farID)
	log.Println("qerID:", p.qerID)
	log.Println("qci:", p.qci)
	log.Println("needDecap:", p.needDecap)
	log.Println("allocIPFlag:", p.allocIPFlag)
	log.Println("--------------------------------------------")
}

func (p *pdr) parsePDI(pdiIEs []*ie.IE, appPFDs map[string]appPFD, upf *upf) error {
	var ueIP4 net.IP

	for _, pdiIE := range pdiIEs {
		switch pdiIE.Type {
		case ie.UEIPAddress:
			ueIPaddr, err := pdiIE.UEIPAddress()
			if err != nil {
				log.Println("Failed to parse UE IP address")
				continue
			}

			if needAllocIP(ueIPaddr) {
				/* alloc IPV6 if CHV6 is enabled : TBD */
				log.Println("UPF should alloc UE IP. CHV4 flag set")
				ueIP4, err = upf.ippool.allocIPV4()
				if err != nil {
					log.Println("failed to allocate UE IP")
					return err
				}
				p.allocIPFlag = true
				log.Println("ueipv4 : ", ueIP4.String())
			} else {
				ueIP4 = ueIPaddr.IPv4Address
			}
		case ie.SourceInterface:
			srcIface, err := pdiIE.SourceInterface()
			if err != nil {
				log.Println("Failed to parse Source Interface IE!")
				continue
			}

			if srcIface == ie.SrcInterfaceCPFunction {
				log.Println("Source Interface CP Function not supported yet")
			} else if srcIface == ie.SrcInterfaceAccess {
				p.srcIface = access
				p.srcIfaceMask = 0xFF
			} else if srcIface == ie.SrcInterfaceCore {
				p.srcIface = core
				p.srcIfaceMask = 0xFF
			}
		case ie.FTEID:
			fteid, err := pdiIE.FTEID()
			if err != nil {
				log.Println("Failed to parse FTEID IE")
				continue
			}
			teid := fteid.TEID
			tunnelIPv4Address := fteid.IPv4Address

			if teid != 0 {
				p.tunnelTEID = teid
				p.tunnelTEIDMask = 0xFFFFFFFF
				p.tunnelIP4Dst = ip2int(tunnelIPv4Address)
				p.tunnelIP4DstMask = 0xFFFFFFFF
				log.Println("TunnelIPv4Address:", tunnelIPv4Address)
			}
		case ie.QFI:
			qfi, err := pdiIE.QFI()
			if err != nil {
				log.Println("Failed to parse QFI IE")
				p.qci = 0
			}

			log.Println("Pdr QFI IE : ", qfi)
			p.qci = uint32(qfi)
		}
	}

	// Needed if SDF filter is bad or absent
	if len(ueIP4) == 4 {
		if p.srcIface == core {
			p.dstIP = ip2int(ueIP4)
			p.dstIPMask = 0xffffffff // /32
		} else if p.srcIface == access {
			p.srcIP = ip2int(ueIP4)
			p.srcIPMask = 0xffffffff // /32
		}
	}

	for _, ie2 := range pdiIEs {
		switch ie2.Type {
		case ie.ApplicationID:

			appID, err := ie2.ApplicationID()
			if err != nil {
				log.Println("Unable to parse Application ID", err)
				continue
			}

			apfd, ok := appPFDs[appID]
			if !ok {
				log.Println("Unable to find Application ID", err)
				continue
			}
			if appID != apfd.appID {
				log.Fatalln("Mismatch in App ID", appID, apfd.appID)
			}
			log.Println("inside application id", apfd.appID, apfd.flowDescs)
			for _, flowDesc := range apfd.flowDescs {
				log.Println("flow desc", flowDesc)
				var ipf ipFilterRule
				err = ipf.parseFlowDesc(flowDesc, ueIP4.String())
				if err != nil {
					return errBadFilterDesc
				}

				if (p.srcIface == access && ipf.direction == "out") || (p.srcIface == core && ipf.direction == "in") {
					log.Println("Found a match", p.srcIface, flowDesc)
					if ipf.proto != reservedProto {
						p.proto = ipf.proto
						p.protoMask = reservedProto
					}
					// TODO: Verify assumption that flow description in case of PFD is to be taken as-is
					p.dstIP = ip2int(ipf.dst.IPNet.IP)
					p.dstIPMask = ipMask2int(ipf.dst.IPNet.Mask)
					p.srcIP = ip2int(ipf.src.IPNet.IP)
					p.srcIPMask = ipMask2int(ipf.src.IPNet.Mask)

					break
				}
			}
		case ie.SDFFilter:
			// Do nothing for the time being
			sdfFields, err := ie2.SDFFilter()
			if err != nil {
				log.Println("Unable to parse SDF filter!")
				continue
			}

			flowDesc := sdfFields.FlowDescription
			if flowDesc == "" {
				log.Println("Empty SDF filter description!")
				// TODO: Implement referencing SDF ID
				continue
			}
			log.Println("Flow Description is:", flowDesc)

			var ipf ipFilterRule
			err = ipf.parseFlowDesc(flowDesc, ueIP4.String())
			if err != nil {
				return errBadFilterDesc
			}

			if ipf.proto != reservedProto {
				p.proto = ipf.proto
				p.protoMask = reservedProto
			}

			if p.srcIface == core {
				p.dstIP = ip2int(ipf.dst.IPNet.IP)
				p.dstIPMask = ipMask2int(ipf.dst.IPNet.Mask)
				p.srcIP = ip2int(ipf.src.IPNet.IP)
				p.srcIPMask = ipMask2int(ipf.src.IPNet.Mask)
			} else if p.srcIface == access {
				p.srcIP = ip2int(ipf.dst.IPNet.IP)
				p.srcIPMask = ipMask2int(ipf.dst.IPNet.Mask)
				p.dstIP = ip2int(ipf.src.IPNet.IP)
				p.dstIPMask = ipMask2int(ipf.src.IPNet.Mask)
			}
		}
	}

	return nil
}

func (p *pdr) parsePDR(ie1 *ie.IE, seid uint64, appPFDs map[string]appPFD, upf *upf) error {
	/* reset outerHeaderRemoval to begin with */
	outerHeaderRemoval := uint8(0)

	pdrID, err := ie1.PDRID()
	if err != nil {
		log.Println("Could not read PDR ID!")
		return nil
	}

	precedence, err := ie1.Precedence()
	if err != nil {
		log.Println("Could not read Precedence!")
		return nil
	}

	pdi, err := ie1.PDI()
	if err != nil {
		log.Println("Could not read PDI!")
		return nil
	}

	res, err := ie1.OuterHeaderRemovalDescription()
	if res == 0 && err == nil { // 0 == GTP-U/UDP/IPv4
		outerHeaderRemoval = 1
	}

	err = p.parsePDI(pdi, appPFDs, upf)
	if err != nil && err != errBadFilterDesc {
		return err
	}

	farID, err := ie1.FARID()
	if err != nil {
		log.Println("Could not read FAR ID!")
		return nil
	}

	qerID, err := ie1.QERID()
	if err != nil {
		log.Println("Could not read QER ID!")
	}

	p.precedence = precedence
	p.pdrID = uint32(pdrID)
	p.fseID = (seid) // fseID currently being truncated to uint32 <--- FIXIT/TODO/XXX
	p.ctrID = 0      // ctrID currently not being set <--- FIXIT/TODO/XXX
	p.farID = farID  // farID currently not being set <--- FIXIT/TODO/XXX
	p.qerID = qerID
	p.needDecap = outerHeaderRemoval

	return nil
}
