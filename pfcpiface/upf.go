// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2020 Intel Corporation

package main

import (
	"log"
	"net"
	"time"
)

// QosConfigVal : Qos configured value
type QosConfigVal struct {
	cbs              uint32
	pbs              uint32
	ebs              uint32
	schedulePriority uint32
}

type upf struct {
	enableUeIPAlloc  bool
	enableEndMarker  bool
	accessIface      string
	coreIface        string
	ippoolCidr       string
	accessIP         net.IP
	coreIP           net.IP
	n4SrcIP          net.IP
	nodeIP           net.IP
	fqdnHost         string
	maxSessions      uint32
	connTimeout      time.Duration
	readTimeout      time.Duration
	simInfo          *SimModeInfo
	intf             fastPath
	ippool           ipPool
	recoveryTime     time.Time
	dnn              string
	reportNotifyChan chan uint64
	qciQosMap        map[uint8]*QosConfigVal
}

// to be replaced with go-pfcp structs

// Don't change these values
const (
	tunnelGTPUPort = 2152

	// src-iface consts
	core   = 0x2
	access = 0x1

	// far-id specific directions
	n3 = 0x0
	n6 = 0x1
	n9 = 0x2

	// far-action specific values
	farForwardD = 0x0
	farForwardU = 0x1
	farDrop     = 0x2
	farBuffer   = 0x3
	farNotify   = 0x4
)

func (u *upf) sendMsgToUPF(method string, pdrs []pdr, fars []far, qers []qer) uint8 {
	return u.intf.sendMsgToUPF(method, pdrs, fars, qers)
}

func (u *upf) sendEndMarkers(endMarkerList *[][]byte) error {
	return u.intf.sendEndMarkers(endMarkerList)
}

func sendDeleteAllSessionsMsgtoUPF(u *upf) {
	u.intf.sendDeleteAllSessionsMsgtoUPF()
}

func (u *upf) isConnected() bool {
	return u.intf.isConnected(&u.accessIP)
}

func (u *upf) exit() {
	u.intf.exit()
}

func (u *upf) sim(method string) {
	u.intf.sim(u, method)
}

func (u *upf) readQciQosMap(conf *Conf) {
	u.qciQosMap = make(map[uint8]*QosConfigVal)
	for _, qosVal := range conf.QciQosConfig {
		qosConfigVal := &QosConfigVal{
			cbs:              qosVal.CBS,
			ebs:              qosVal.EBS,
			pbs:              qosVal.PBS,
			schedulePriority: qosVal.SchedulingPriority,
		}
		u.qciQosMap[qosVal.QCI] = qosConfigVal
	}
}

func (u *upf) setUpfInfo(conf *Conf) {
	u.reportNotifyChan = make(chan uint64, 1024)
	u.n4SrcIP = net.ParseIP("0.0.0.0")
	u.nodeIP = net.ParseIP("0.0.0.0")

	u.readQciQosMap(conf)
	if conf.CPIface.SrcIP == "" {
		if conf.CPIface.DestIP != "" {
			log.Println("Dest address ", conf.CPIface.DestIP)
			u.n4SrcIP = getLocalIP(conf.CPIface.DestIP)
			log.Println("SPGWU/UPF address IP: ", u.n4SrcIP.String())
		}
	} else {
		addrs, errin := net.LookupHost(conf.CPIface.SrcIP)
		if errin == nil {
			u.n4SrcIP = net.ParseIP(addrs[0])
		}
	}

	if conf.CPIface.FQDNHost != "" {
		ips, err := net.LookupHost(conf.CPIface.FQDNHost)
		if err == nil {
			u.nodeIP = net.ParseIP(ips[0])
		}
	}
	log.Println("UPF Node IP : ", u.nodeIP.String())
	log.Println("UPF Local IP : ", u.n4SrcIP.String())
	u.intf.setUpfInfo(u, conf)
}

func (u *upf) setInfo(udpConn *net.UDPConn, udpAddr net.Addr, pconn *PFCPConn) {
	u.intf.setInfo(udpConn, udpAddr, pconn)
}
