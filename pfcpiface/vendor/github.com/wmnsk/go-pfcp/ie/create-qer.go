// Copyright 2019-2020 go-pfcp authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package ie

// NewCreateQER creates a new CreateQER IE.
func NewCreateQER(qer, qci, gate, mbr, gbr, pktRate, prStatus, dlflm, qfi, rQoS, ppi, aw, qInd *IE) *IE {
	return newGroupedIE(CreateQER, 0, qer, qci, gate, mbr, gbr, pktRate, prStatus, dlflm, qfi, rQoS, ppi, aw, qInd)
}

// CreateQER returns the IEs above CreateQER if the type of IE matches.
func (i *IE) CreateQER() ([]*IE, error) {
	if i.Type != CreateQER {
		return nil, &InvalidTypeError{Type: i.Type}
	}

	return ParseMultiIEs(i.Payload)
}
