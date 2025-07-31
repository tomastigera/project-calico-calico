// Copyright (c) 2025 Tigera, Inc. All rights reserved

package ipsetmember

import (
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/ip"
)

func MakeDomain(domain string) DomainIPSetMember {
	return domainIPSetMember{domain: domain}
}

type DomainIPSetMember interface {
	IPSetMember
	Domain() string
}

type domainIPSetMember struct {
	domain string
}

func (m domainIPSetMember) ToProtobufFormat() string {
	return m.domain
}

func (m domainIPSetMember) String() string {
	return fmt.Sprintf("%T(%s)", m, m.ToProtobufFormat())
}

func (m domainIPSetMember) Domain() string {
	return m.domain
}

type PortOnlyIPSetMember interface {
	IPSetMember
	PortNumber() uint16
	Family() int
	PortOnlyIPSetMember() // No-op marker method
}

func MakePortOnly(port uint16, family int) PortOnlyIPSetMember {
	return portOnlyIPSetMember{
		port:   port,
		family: family,
	}
}

type portOnlyIPSetMember struct {
	port   uint16
	family int
}

func (m portOnlyIPSetMember) PortOnlyIPSetMember() {}

func (m portOnlyIPSetMember) ToProtobufFormat() string {
	return fmt.Sprintf("v%d,%d", m.Family(), m.PortNumber())
}

func (m portOnlyIPSetMember) String() string {
	return fmt.Sprintf("%T(%s)", m, m.ToProtobufFormat())
}

func (m portOnlyIPSetMember) PortNumber() uint16 {
	return m.port
}

func (m portOnlyIPSetMember) Family() int {
	return m.family
}

func MakeEgressGateway(
	addr ip.V4Addr,
	deletionTimestamp time.Time,
	deletionGracePeriodSeconds int64,
	hostname string,
	healthPort uint16,
) EgressGatewayIPSetMember {
	return egressGatewayIPSetMember{
		addr:                       addr,
		deletionTimestamp:          deletionTimestamp,
		deletionGracePeriodSeconds: deletionGracePeriodSeconds,
		hostname:                   hostname,
		healthPort:                 healthPort,
	}
}

type EgressGatewayIPSetMember interface {
	IPSetMember
	Addr() ip.Addr
	CIDR() ip.CIDR
	HealthPort() uint16
	DeletionTimestamp() time.Time
	DeletionGracePeriodSeconds() int64
	Hostname() string
}

type egressGatewayIPSetMember struct {
	addr                       ip.V4Addr
	hostname                   string
	deletionTimestamp          time.Time
	deletionGracePeriodSeconds int64
	healthPort                 uint16
}

func (m egressGatewayIPSetMember) ToProtobufFormat() string {
	start, finish := m.protoMaintenanceTimes()
	return fmt.Sprintf("%s,%s,%s,%d,%s",
		m.CIDR().String(), // Dataplane expects the CIDR format.
		start,
		finish,
		m.HealthPort(),
		m.Hostname(),
	)
}

func (m egressGatewayIPSetMember) protoMaintenanceTimes() (start, finish string) {
	maintenanceFinished := m.DeletionTimestamp()
	if maintenanceFinished.IsZero() {
		return
	}
	maintenanceStarted := maintenanceFinished.Add(-time.Second * time.Duration(m.DeletionGracePeriodSeconds()))
	startBytes, err := maintenanceStarted.MarshalText()
	if err != nil {
		log.WithField("member", m).Warnf("unable to marshal start timestamp to text, defaulting to empty str: %s", maintenanceStarted)
		return
	}
	finishBytes, err := maintenanceFinished.MarshalText()
	if err != nil {
		log.WithField("member", m).Warnf("unable to marshal end timestamp to text, defaulting to empty str: %s", maintenanceFinished)
		return
	}
	return string(startBytes), string(finishBytes)
}

func (m egressGatewayIPSetMember) String() string {
	return fmt.Sprintf("%T(%v,%v,%v,%v,%v)", m, m.Addr(), m.DeletionTimestamp(), m.DeletionGracePeriodSeconds(), m.HealthPort(), m.Hostname())
}

func (m egressGatewayIPSetMember) Addr() ip.Addr {
	return m.addr
}

func (m egressGatewayIPSetMember) CIDR() ip.CIDR {
	return m.addr.AsCIDR()
}

func (m egressGatewayIPSetMember) HealthPort() uint16 {
	return m.healthPort
}

func (m egressGatewayIPSetMember) DeletionTimestamp() time.Time {
	return m.deletionTimestamp
}

func (m egressGatewayIPSetMember) DeletionGracePeriodSeconds() int64 {
	return m.deletionGracePeriodSeconds
}

func (m egressGatewayIPSetMember) Hostname() string {
	return m.hostname
}
