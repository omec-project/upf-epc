// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2020 Intel Corporation

package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
)

//ctrType
const (
	preQosPdrCounter  uint8 = 0 //Pre qos pdr ctr
	postQosPdrCounter uint8 = 1 //Post qos pdr ctr
)

type counter struct {
	maxSize   uint64
	allocated map[uint64]uint64
	free      map[uint64]uint64
}

func (c *counter) init() {
	c.allocated = make(map[uint64]uint64)
	c.free = make(map[uint64]uint64)
}

func (p *p4rtc) setCounterSize(counterID uint8, name string) error {
	if p.p4client != nil {
		for _, ctr := range p.p4client.P4Info.Counters {
			if ctr.Preamble.Name == name {
				p.counters[counterID].maxSize = uint64(ctr.Size)
				return nil
			}
		}
	}

	errin := fmt.Errorf("Countername not found %s", name)
	return errin
}

func (p *p4rtc) resetCounterVal(counterID uint8, val uint64) {
	log.Println("delete counter val ", val)
	delete(p.counters[counterID].allocated, val)
	//p.counters[counterID].free[val] = 1
}

func (p *p4rtc) getCounterVal(counterID uint8, pdrID uint32) (uint64, error) {
	/*
	   loop :
	      random counter generate
	      check allocated map
	      if not in map then return counter val.
	      if present continue
	      if loop reaches max break and fail.
	*/
	ctr := &p.counters[counterID]
	var val uint64
	for i := 0; i < int(ctr.maxSize); i++ {
		rand.Seed(time.Now().UnixNano())
		val = uint64(rand.Intn(int(ctr.maxSize)-1) + 1)
		if _, ok := ctr.allocated[val]; !ok {
			log.Println("key not in allocated map ", val)
			return val, nil
		}
	}

	errin := fmt.Errorf("key alloc fail %v", val)
	return 0, errin
}

type p4rtc struct {
	accessIP     net.IP
	accessIPMask net.IPMask
	n4SrcIP      net.IP
	coreIP       net.IP
	host         string
	fqdnh        string
	deviceID     uint64
	timeout      uint32
	p4rtcServer  string
	p4rtcPort    string
	p4client     *P4rtClient
	counters     []counter
}

func (p *p4rtc) getAccessIP(val *string) {
	*val = p.accessIP.String()
}

func (p *p4rtc) getCoreIP(val *string) {
	*val = p.coreIP.String()
}

func (p *p4rtc) getN4SrcIP(val *string) {
	*val = p.n4SrcIP.String()
}

func (p *p4rtc) getUpfInfo(conf *Conf, u *upf) {
	log.Println("getUpfInfo p4rtc")
	u.accessIface = conf.AccessIface.IfName
	u.coreIface = conf.CoreIface.IfName
	u.accessIP = p.accessIP
	u.coreIP = p.coreIP
	u.fqdnHost = p.fqdnh
	u.maxSessions = conf.MaxSessions
}

func channelSetup(p *p4rtc) (*P4rtClient, error) {
	log.Println("Channel Setup.")
	localclient, errin := CreateChannel(p.host,
		p.deviceID, p.timeout)
	if errin != nil {
		log.Println("create channel failed : ", errin)
		return nil, errin
	}
	if localclient != nil {
		log.Println("device id ", (*localclient).DeviceID)
		p.accessIP, p.accessIPMask, errin =
			setSwitchInfo(localclient)
		if errin != nil {
			log.Println("Switch set info failed ", errin)
			return nil, errin
		}
		log.Println("accessIP, Mask ", p.accessIP, p.accessIPMask)

	} else {
		log.Println("p4runtime client is null.")
		return nil, errin
	}

	return localclient, nil
}

func (p *p4rtc) initCounter() error {
	log.Println("Initialize counters for p4client.")
	var errin error
	if p.p4client == nil {
		errin = fmt.Errorf("Can't initialize counter. P4client null.")
		return errin
	}

	p.counters = make([]counter, 2)
	errin = p.setCounterSize(preQosPdrCounter,
		"PreQosPipe.pre_qos_pdr_counter")
	if errin != nil {
		log.Println("preQosPdrCounter counter not found : ", errin)
	}
	errin = p.setCounterSize(postQosPdrCounter,
		"PostQosPipe.post_qos_pdr_counter")
	if errin != nil {
		log.Println("postQosPdrCounter counter not found : ", errin)
	}
	for i := range p.counters {
		log.Println("init maps for counters.")
		p.counters[i].init()
	}

	return nil
}

func (p *p4rtc) handleChannelStatus() bool {
	var errin error
	if p.p4client == nil || p.p4client.CheckStatus() != Ready {
		p.p4client, errin = channelSetup(p)
		if errin != nil {
			log.Println("create channel failed : ", errin)
			return true
		}
		errin = p.initCounter()
		if errin != nil {
			log.Println("Counter Init failed. : ", errin)
			return true
		}
	}

	return false
}

func (p *p4rtc) sendDeleteAllSessionsMsgtoUPF(upf *upf) {
	log.Println("Loop through sessions and delete all entries p4")
	for _, value := range sessions {
		p.sendMsgToUPF("del", value.pdrs, value.fars, upf)
	}
}

func (p *p4rtc) parseFunc(conf *Conf) {
	log.Println("parseFunc p4rtc")
	var errin error
	p.accessIP, p.accessIPMask = ParseStrIP(conf.P4rtcIface.AccessIP)
	log.Println("AccessIP: ", p.accessIP,
		", AccessIPMask: ", p.accessIPMask)
	p.p4rtcServer = conf.P4rtcIface.P4rtcServer
	log.Println("p4rtc server ip/name", p.p4rtcServer)
	p.p4rtcPort = conf.P4rtcIface.P4rtcPort

	if *p4RtcServerIP != "" {
		p.p4rtcServer = *p4RtcServerIP
	}

	if *p4RtcServerPort != "" {
		p.p4rtcPort = *p4RtcServerPort
	}

	if *n4SrcIPStr != "" {
		p.n4SrcIP = net.ParseIP(*n4SrcIPStr)
	} else {
		p.n4SrcIP = net.ParseIP("0.0.0.0")
	}

	log.Println("onos server ip ", p.p4rtcServer)
	log.Println("onos server port ", p.p4rtcPort)
	log.Println("n4 ip ", p.n4SrcIP.String())

	p.host = p.p4rtcServer + ":" + p.p4rtcPort
	log.Println("server name: ", p.host)
	p.deviceID = 1
	p.timeout = 30
	p.p4client, errin = channelSetup(p)
	if errin != nil {
		fmt.Printf("create channel failed : %v\n", errin)
	}

	errin = p.initCounter()
	if errin != nil {
		log.Println("Counter Init failed. : ", errin)
	}
}

func (p *p4rtc) sendMsgToUPF(method string, pdrs []pdr,
	fars []far, u *upf) uint8 {
	log.Println("sendMsgToUPF p4")
	var funcType uint8
	var err error
	var val uint64
	var cause uint8 = ie.CauseRequestRejected
	var fseidIP uint32
	log.Println("Access IP ", u.accessIP.String())
	fseidIP = binary.LittleEndian.Uint32(u.accessIP.To4())
	log.Println("fseidIP ", fseidIP)
	switch method {
	case "add":
		{
			funcType = FunctionTypeInsert
			for i := range pdrs {
				pdrs[i].fseidIP = fseidIP
				val, err = p.getCounterVal(
					preQosPdrCounter, pdrs[i].pdrID)
				if err != nil {
					log.Println("Counter id alloc failed ", err)
					return cause
				}
				pdrs[i].ctrID = uint32(val)
			}

			for j := range fars {
				fars[j].fseidIP = fseidIP
			}
		}
	case "del":
		{
			funcType = FunctionTypeDelete
			for i := range pdrs {
				p.resetCounterVal(preQosPdrCounter,
					uint64(pdrs[i].ctrID))
			}
		}
	case "mod":
		{
			funcType = FunctionTypeUpdate
			for j := range fars {
				fars[j].fseidIP = fseidIP
			}
		}
	default:
		{
			log.Println("Unknown method : ", method)
			return cause
		}
	}

	for _, pdr := range pdrs {
		errin := p.p4client.WritePdrTable(pdr, funcType)
		if errin != nil {
			log.Println("pdr entry function failed ", errin)
			return cause
		}
	}

	for _, far := range fars {
		errin := p.p4client.WriteFarTable(far, funcType)
		if errin != nil {
			log.Println("far entry function failed ", errin)
			return cause
		}
	}

	cause = ie.CauseRequestAccepted
	return cause
}