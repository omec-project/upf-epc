// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2020 Intel Corporation

package main

import (
	"log"

	"github.com/wmnsk/go-pfcp/ie"
)

type qer struct {
	qerID    uint32
	qfi      uint8
	srcIface uint8
	ulStatus uint8
	dlStatus uint8
	cir      uint64
	pir      uint64
	cbs      uint64
	ebs      uint64
	pbs      uint64
	ulMbr    uint64
	dlMbr    uint64
	ulGbr    uint64
	dlGbr    uint64
	fseID    uint64
	fseidIP  uint32
}

func (q *qer) printQER() {
	log.Println("------------------ QER ---------------------")
	log.Println("QER ID:", q.qerID)
	log.Println("fseID:", q.fseID)
	log.Println("Src Interface:", q.srcIface)
	log.Println("QFI:", q.qfi)
	log.Println("fseIDIP:", int2ip(q.fseidIP))
	log.Println("Uplink Status:", q.ulStatus)
	log.Println("Downling Status:", q.dlStatus)
	log.Println("Uplink MBR:", q.ulMbr)
	log.Println("Downlink MBR:", q.dlMbr)
	log.Println("Uplink GBR:", q.ulGbr)
	log.Println("Downlink GBR:", q.dlGbr)
	log.Println("Committed Information rate:", q.cir)
	log.Println("Peak Information rate:", q.pir)
	log.Println("Committed burst size:", q.cbs)
	log.Println("Peak burst size:", q.pbs)
	log.Println("Excess burst size:", q.pbs)
	log.Println("--------------------------------------------")
}
func (q *qer) parseQER(ie1 *ie.IE, seid uint64, upf *upf) error {

	qerID, err := ie1.QERID()
	if err != nil {
		log.Println("Could not read QER ID!")
		return nil
	}

	qfi, err := ie1.QFI()
	if err != nil {
		log.Println("Could not read QFI!")
	}

	gsUL, err := ie1.GateStatusUL()
	if err != nil {
		log.Println("Could not read Gate status uplink!")
	}

	gsDL, err := ie1.GateStatusDL()
	if err != nil {
		log.Println("Could not read Gate status downlink!")
	}

	mbrUL, err := ie1.MBRUL()
	if err != nil {
		log.Println("Could not read MBRUL!")
	}

	mbrDL, err := ie1.MBRDL()
	if err != nil {
		log.Println("Could not read MBRDL!")
	}

	gbrUL, err := ie1.GBRUL()
	if err != nil {
		log.Println("Could not read GBRUL!")
	}

	gbrDL, err := ie1.GBRDL()
	if err != nil {
		log.Println("Could not read GBRDL!")
	}

	q.qerID = uint32(qerID)
	q.qfi = uint8(qfi)
	q.ulStatus = uint8(gsUL)
	q.dlStatus = uint8(gsDL)
	q.ulMbr = uint64(mbrUL)
	q.dlMbr = uint64(mbrDL)
	q.ulGbr = uint64(gbrUL)
	q.dlGbr = uint64(gbrDL)
	q.cir = q.dlGbr
	q.pir = q.dlMbr
	q.cbs = uint64(upf.qciQosMap[qfi].cbs)
	q.pbs = uint64(upf.qciQosMap[qfi].pbs)
	q.ebs = uint64(upf.qciQosMap[qfi].ebs)
	q.fseID = (seid) // fseID currently being truncated to uint32 <--- FIXIT/TODO/XXX

	return nil
}
