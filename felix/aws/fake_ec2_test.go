// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package aws

import (
	"context"
	encoding_binary "encoding/binary"
	"fmt"
	"net"
	"reflect"
	"slices"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/testutils"
)

const (
	instanceTypeT0Pico types.InstanceType = "t0.pico"
)

type fakeEC2 struct {
	lock sync.Mutex

	Errors testutils.ErrorProducer

	IgnoreNextUnassignPrivateIpAddresses bool
	IgnoreNextAssignPrivateIpAddresses   bool

	InstancesByID map[string]types.Instance
	ENIsByID      map[string]types.NetworkInterface

	SubnetsByID    map[string]types.Subnet
	nextENINum     int
	nextAttachNum  int
	nextAssocNum   int
	ElasticIPsByID map[string]*types.Address

	postDescribeAddressesActions []func()
	alreadyAssocTriggered        bool
}

func newFakeEC2Client() (*EC2Client, *fakeEC2) {
	mockEC2 := &fakeEC2{
		InstancesByID:  map[string]types.Instance{},
		ENIsByID:       map[string]types.NetworkInterface{},
		SubnetsByID:    map[string]types.Subnet{},
		ElasticIPsByID: map[string]*types.Address{},

		Errors: testutils.NewErrorProducer(testutils.WithErrFactory(func(queueName string) error {
			return errBadParam(queueName, "ErrorFactory.Error")
		})),

		nextENINum:    0x1000,
		nextAttachNum: 0x1000,
	}
	return &EC2Client{
		EC2Svc:     mockEC2,
		InstanceID: instanceID,
	}, mockEC2
}

func (f *fakeEC2) nextENIAttachID() string {
	id := fmt.Sprintf("attach-%017x", f.nextAttachNum)
	f.nextAttachNum++
	return id
}

func (f *fakeEC2) nextEIPAssocID() string {
	id := fmt.Sprintf("eipassoc-%017x", f.nextAssocNum)
	f.nextAssocNum++
	return id
}

func (f *fakeEC2) addSubnet(id string, az string, cidr string) {
	f.SubnetsByID[id] = types.Subnet{
		AvailabilityZone: stringPtr(az),
		VpcId:            stringPtr(testVPC),
		SubnetId:         stringPtr(id),
		CidrBlock:        stringPtr(cidr),
	}
}

func (f *fakeEC2) addElasticIP(id string, addr ip.Addr) {
	f.ElasticIPsByID[id] = &types.Address{
		AllocationId: stringPtr(id),
		PublicIp:     stringPtr(addr.String()),
	}
}

func (f *fakeEC2) DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	f.lock.Lock()
	defer f.lock.Unlock()

	if err := f.Errors.NextErrorByCaller(); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if len(params.InstanceIds) != 1 {
		panic("fakeEC2 can't handle !=1 instance ID")
	}
	if len(optFns) > 0 {
		panic("fakeEC2 doesn't understand opts")
	}
	if inst, ok := f.InstancesByID[params.InstanceIds[0]]; !ok {
		return nil, errNotFound("DescribeInstances", "InvalidInstanceID.NotFound")
	} else {
		return &ec2.DescribeInstancesOutput{
			Reservations: []types.Reservation{
				{
					Instances: []types.Instance{
						inst,
					},
				},
			},
		}, nil
	}
}

func (f *fakeEC2) ModifyNetworkInterfaceAttribute(ctx context.Context, params *ec2.ModifyNetworkInterfaceAttributeInput, optFns ...func(*ec2.Options)) (*ec2.ModifyNetworkInterfaceAttributeOutput, error) {
	f.lock.Lock()
	defer f.lock.Unlock()

	if err := f.Errors.NextErrorByCaller(); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(optFns) > 0 {
		panic("fakeEC2 doesn't understand opts")
	}
	if params.NetworkInterfaceId == nil {
		panic("BUG: missing NetworkInterfaceId")
	}
	eni, ok := f.ENIsByID[*params.NetworkInterfaceId]
	if !ok {
		return nil, errNotFound("ModifyNetworkInterfaceAttribute", "InvalidNetworkInterfaceId.NotFound")
	}
	if params.SourceDestCheck != nil {
		eni.SourceDestCheck = params.SourceDestCheck.Value
	}
	if params.Attachment != nil {
		if params.Attachment.AttachmentId == nil ||
			!reflect.DeepEqual(params.Attachment.AttachmentId, eni.Attachment.AttachmentId) {
			return nil, errBadParam("ModifyNetworkInterfaceAttribute", "AttachmentID didn't match")
		}
		if params.Attachment.DeleteOnTermination == nil {
			panic("BUG: expecting DeleteOnTermination flag")
		}
		eni.Attachment.DeleteOnTermination = params.Attachment.DeleteOnTermination
		for _, instIface := range f.InstancesByID[*eni.Attachment.InstanceId].NetworkInterfaces {
			if *instIface.NetworkInterfaceId == *eni.NetworkInterfaceId {
				instIface.Attachment.DeleteOnTermination = params.Attachment.DeleteOnTermination
			}
		}
	}
	f.ENIsByID[*params.NetworkInterfaceId] = eni

	return &ec2.ModifyNetworkInterfaceAttributeOutput{}, nil
}

func (f *fakeEC2) DescribeSubnets(ctx context.Context, params *ec2.DescribeSubnetsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	f.lock.Lock()
	defer f.lock.Unlock()

	if err := f.Errors.NextErrorByCaller(); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(optFns) > 0 {
		panic("fakeEC2 doesn't understand opts")
	}

	if params.DryRun != nil || params.MaxResults != nil || params.NextToken != nil {
		panic("fakeEC2 doesn't support requested feature")
	}

	var subnets []types.Subnet
	for _, subnet := range f.SubnetsByID {
		allFiltersMatch := true
		for _, f := range params.Filters {
			filterMatches := false
			switch *f.Name {
			case "availability-zone":
				if slices.Contains(f.Values, *subnet.AvailabilityZone) {
					filterMatches = true
				}
			case "vpc-id":
				if slices.Contains(f.Values, *subnet.VpcId) {
					filterMatches = true
				}
			default:
				panic("fakeEC2 doesn't understand filter " + *f.Name)
			}
			allFiltersMatch = allFiltersMatch && filterMatches
		}
		if !allFiltersMatch {
			continue
		}

		// ENI matches
		subnets = append(subnets, subnet)
	}

	return &ec2.DescribeSubnetsOutput{
		Subnets: subnets,
	}, nil
}

func (f *fakeEC2) DescribeInstanceTypes(ctx context.Context, params *ec2.DescribeInstanceTypesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstanceTypesOutput, error) {
	f.lock.Lock()
	defer f.lock.Unlock()

	if err := f.Errors.NextErrorByCaller(); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(optFns) > 0 {
		panic("fakeEC2 doesn't understand opts")
	}

	if params.DryRun != nil || params.MaxResults != nil || params.NextToken != nil {
		panic("fakeEC2 doesn't support requested feature")
	}
	if len(params.InstanceTypes) != 1 {
		panic("fakeEC2 can't handle !=1 instance type")
	}
	switch params.InstanceTypes[0] {
	case types.InstanceTypeT3Large:
		return &ec2.DescribeInstanceTypesOutput{
			InstanceTypes: []types.InstanceTypeInfo{
				{
					InstanceType: types.InstanceTypeT3Large,
					NetworkInfo: &types.NetworkInfo{
						Ipv4AddressesPerInterface: int32Ptr(12),
						Ipv6AddressesPerInterface: int32Ptr(12),
						Ipv6Supported:             boolPtr(true),
						MaximumNetworkCards:       int32Ptr(1),
						MaximumNetworkInterfaces:  int32Ptr(3),
						NetworkCards: []types.NetworkCardInfo{
							{
								MaximumNetworkInterfaces: int32Ptr(3),
								NetworkCardIndex:         int32Ptr(0),
							},
						},
					},
				},
			},
		}, nil
	case instanceTypeT0Pico:
		// Made up type without any secondary ENI capacity.
		return &ec2.DescribeInstanceTypesOutput{
			InstanceTypes: []types.InstanceTypeInfo{
				{
					InstanceType: instanceTypeT0Pico,
					NetworkInfo: &types.NetworkInfo{
						Ipv4AddressesPerInterface: int32Ptr(1),
						Ipv6AddressesPerInterface: int32Ptr(1),
						Ipv6Supported:             boolPtr(true),
						MaximumNetworkCards:       int32Ptr(1),
						MaximumNetworkInterfaces:  int32Ptr(2),
						NetworkCards: []types.NetworkCardInfo{
							{
								MaximumNetworkInterfaces: int32Ptr(2),
								NetworkCardIndex:         int32Ptr(0),
							},
						},
					},
				},
			},
		}, nil
	default:
		panic("unknown instance type")
	}
}

func (f *fakeEC2) DescribeNetworkInterfaces(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	f.lock.Lock()
	defer f.lock.Unlock()

	if err := f.Errors.NextErrorByCaller(); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(optFns) > 0 {
		panic("fakeEC2 doesn't understand opts")
	}

	if params.DryRun != nil || params.MaxResults != nil || params.NextToken != nil {
		panic("fakeEC2 doesn't support requested feature")
	}

	var ENIs []types.NetworkInterface
	for ENIID, ENI := range f.ENIsByID {
		if params.NetworkInterfaceIds != nil {
			found := false
			for _, id := range params.NetworkInterfaceIds {
				if ENIID == id {
					found = true
				}
			}
			if !found {
				continue
			}
		}

		allFiltersMatch := true
		for _, filter := range params.Filters {
			filterMatches := false
			switch *filter.Name {
			case "attachment.instance-id":
				for _, v := range filter.Values {
					if ENI.Attachment != nil && ENI.Attachment.InstanceId != nil && *ENI.Attachment.InstanceId == v {
						filterMatches = true
						break
					}
				}
			case "status":
				if slices.Contains(filter.Values, string(ENI.Status)) {
					filterMatches = true
				}
			case "tag:calico:instance":
				for _, v := range filter.Values {
					for _, tag := range ENI.TagSet {
						if *tag.Key == "calico:instance" && *tag.Value == v {
							filterMatches = true
							break
						}
					}
				}
			default:
				panic("fakeEC2 doesn't understand filter " + *filter.Name)
			}
			allFiltersMatch = allFiltersMatch && filterMatches
		}
		if !allFiltersMatch {
			continue
		}

		// ENI matches
		ENIs = append(ENIs, ENI)
	}

	// DescribeNetworkInterfaces seems to return an empty list rather than a not-found error.
	return &ec2.DescribeNetworkInterfacesOutput{
		NetworkInterfaces: ENIs,
	}, nil
}

func (f *fakeEC2) CreateNetworkInterface(ctx context.Context, params *ec2.CreateNetworkInterfaceInput, optFns ...func(*ec2.Options)) (*ec2.CreateNetworkInterfaceOutput, error) {
	f.lock.Lock()
	defer f.lock.Unlock()

	if err := f.Errors.NextErrorByCaller(); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(optFns) > 0 {
		panic("fakeEC2 doesn't understand opts")
	}

	if params.DryRun != nil || len(params.PrivateIpAddresses) > 0 {
		panic("fakeEC2 doesn't support requested feature")
	}
	if *params.SubnetId != subnetIDWest1Calico && *params.SubnetId != subnetIDWest1CalicoAlt {
		panic("wrong subnet ID" + *params.SubnetId)
	}
	if params.PrivateIpAddress == nil {
		panic("expected specific IP address")
	}

	ENIID := fmt.Sprintf("eni-%017x", f.nextENINum)
	mac := make(net.HardwareAddr, 6)
	encoding_binary.BigEndian.PutUint32(mac[2:], uint32(f.nextENINum))
	f.nextENINum++

	var tags []types.Tag
	for _, tagSpec := range params.TagSpecifications {
		if tagSpec.ResourceType != "network-interface" {
			panic("tag spec missing incorrect resource type")
		}
		tags = append(tags, tagSpec.Tags...)
	}
	var sgs []types.GroupIdentifier

	for _, g := range params.Groups {
		sgs = append(sgs, types.GroupIdentifier{
			GroupId:   stringPtr(g),
			GroupName: stringPtr(g + " name"),
		})
	}

	eni := types.NetworkInterface{
		NetworkInterfaceId: stringPtr(ENIID),
		SubnetId:           params.SubnetId,
		Description:        params.Description,
		Attachment: &types.NetworkInterfaceAttachment{
			Status: types.AttachmentStatusDetached,
		},
		AvailabilityZone: stringPtr(azWest1),
		Groups:           sgs,
		InterfaceType:    "eni",
		MacAddress:       stringPtr(mac.String()),
		PrivateIpAddress: params.PrivateIpAddress,
		PrivateIpAddresses: []types.NetworkInterfacePrivateIpAddress{
			{
				Primary:          boolPtr(true),
				PrivateIpAddress: params.PrivateIpAddress,
			},
		},
		SourceDestCheck: boolPtr(true),
		Status:          types.NetworkInterfaceStatusAvailable,
		TagSet:          tags,
		VpcId:           stringPtr(testVPC),
	}
	f.ENIsByID[ENIID] = eni

	logrus.WithField("ENI", spew.Sdump(eni)).Info("FakeEC2: Created ENI.")

	return &ec2.CreateNetworkInterfaceOutput{
		NetworkInterface: &eni,
	}, nil
}

func (f *fakeEC2) AttachNetworkInterface(ctx context.Context, params *ec2.AttachNetworkInterfaceInput, optFns ...func(*ec2.Options)) (*ec2.AttachNetworkInterfaceOutput, error) {
	f.lock.Lock()
	defer f.lock.Unlock()

	if err := f.Errors.NextErrorByCaller(); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(optFns) > 0 {
		panic("fakeEC2 doesn't understand opts")
	}

	if params.DryRun != nil || params.NetworkCardIndex != nil && *params.NetworkCardIndex != 0 {
		panic("fakeEC2 doesn't support requested feature")
	}

	if params.InstanceId == nil || params.NetworkInterfaceId == nil {
		panic("missing instance ID or ENI ID on attach call")
	}

	inst, ok := f.InstancesByID[*params.InstanceId]
	if !ok {
		return nil, errNotFound("AttachNetworkInterface", "InstanceId.NotFound")
	}
	eni, ok := f.ENIsByID[*params.NetworkInterfaceId]
	if !ok {
		return nil, errNotFound("AttachNetworkInterface", "NetworkInterfaceId.NotFound")
	}

	if eni.Attachment != nil && eni.Attachment.InstanceId != nil {
		return nil, errBadParam("AttachNetworkInterface", "NetworkInterface.AlreadyAttached")
	}

	for _, ni := range inst.NetworkInterfaces {
		if *ni.Attachment.DeviceIndex == *params.DeviceIndex {
			return nil, errBadParam("AttachNetworkInterface", "DeviceIndex.Conflict")
		}
	}

	eni.Attachment = &types.NetworkInterfaceAttachment{
		AttachmentId:        stringPtr(f.nextENIAttachID()),
		DeleteOnTermination: boolPtr(false),
		DeviceIndex:         params.DeviceIndex,
		InstanceId:          params.InstanceId,
		NetworkCardIndex:    int32Ptr(0),
		Status:              types.AttachmentStatusAttached,
	}
	eni.Status = types.NetworkInterfaceStatusAssociated

	var privIPs []types.InstancePrivateIpAddress
	for _, ip := range eni.PrivateIpAddresses {
		privIPs = append(privIPs, types.InstancePrivateIpAddress{
			Primary:          ip.Primary,
			PrivateIpAddress: ip.PrivateIpAddress,
		})
	}
	inst.NetworkInterfaces = append(inst.NetworkInterfaces, types.InstanceNetworkInterface{
		Association: nil,
		Attachment: &types.InstanceNetworkInterfaceAttachment{
			AttachmentId:        eni.Attachment.AttachmentId,
			DeleteOnTermination: boolPtr(false),
			DeviceIndex:         params.DeviceIndex,
			NetworkCardIndex:    int32Ptr(0),
			Status:              types.AttachmentStatusAttached,
		},
		Description:        eni.Description,
		Groups:             eni.Groups,
		InterfaceType:      stringPtr(string(eni.InterfaceType)),
		MacAddress:         eni.MacAddress,
		NetworkInterfaceId: params.NetworkInterfaceId,
		PrivateIpAddress:   eni.PrivateIpAddress,
		PrivateIpAddresses: privIPs,
		SourceDestCheck:    eni.SourceDestCheck,
		Status:             types.NetworkInterfaceStatusAssociated,
		SubnetId:           eni.SubnetId,
		VpcId:              eni.VpcId,
	})

	f.InstancesByID[*params.InstanceId] = inst
	f.ENIsByID[*params.NetworkInterfaceId] = eni

	return &ec2.AttachNetworkInterfaceOutput{
		AttachmentId:     eni.Attachment.AttachmentId,
		NetworkCardIndex: int32Ptr(0),
	}, nil
}

func (f *fakeEC2) DetachNetworkInterface(ctx context.Context, params *ec2.DetachNetworkInterfaceInput, optFns ...func(*ec2.Options)) (*ec2.DetachNetworkInterfaceOutput, error) {
	f.lock.Lock()
	defer f.lock.Unlock()

	if err := f.Errors.NextErrorByCaller(); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(optFns) > 0 {
		panic("fakeEC2 doesn't understand opts")
	}

	if params.Force == nil || !*params.Force {
		panic("Expecting use of Force.")
	}

	var instID string
	found := false
	for ENIID, ENI := range f.ENIsByID {
		if ENI.Attachment != nil && ENI.Attachment.AttachmentId != nil && *ENI.Attachment.AttachmentId == *params.AttachmentId {
			logrus.WithField("id", ENIID).Info("FakeEC2 found ENI to dettach.")
			ENI.Status = types.NetworkInterfaceStatusAvailable
			instID = *ENI.Attachment.InstanceId
			ENI.Attachment = nil
			f.ENIsByID[ENIID] = ENI
			found = true
		}
	}
	if !found {
		return nil, errNotFound("DetachNetworkInterface", "AttachmentId.NotFound")
	}

	inst, ok := f.InstancesByID[instID]
	if !ok {
		panic("FakeEC2: BUG, couldn't find instance for ENI attachment")
	}
	var updatedENIs []types.InstanceNetworkInterface
	found = false
	for _, ENI := range inst.NetworkInterfaces {
		if *ENI.Attachment.AttachmentId == *params.AttachmentId {
			found = true
			continue
		}
		updatedENIs = append(updatedENIs, ENI)
	}
	if !found {
		panic("FakeEC2: BUG, couldn't find ENI on instance")
	}
	inst.NetworkInterfaces = updatedENIs
	f.InstancesByID[instID] = inst

	return &ec2.DetachNetworkInterfaceOutput{ /* not currently used by caller */ }, nil
}

func (f *fakeEC2) AssignPrivateIpAddresses(ctx context.Context, params *ec2.AssignPrivateIpAddressesInput, optFns ...func(*ec2.Options)) (*ec2.AssignPrivateIpAddressesOutput, error) {
	f.lock.Lock()
	defer f.lock.Unlock()

	if err := f.Errors.NextErrorByCaller(); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(optFns) > 0 {
		panic("fakeEC2 doesn't understand opts")
	}

	if params.NetworkInterfaceId == nil {
		return nil, errBadParam("AssignPrivateIpAddresses", "NetworkInterfaceId.Missing")
	}

	if params.AllowReassignment == nil || !*params.AllowReassignment {
		panic("BUG: expecting AllowReassignment to be set")
	}

	if len(params.PrivateIpAddresses) == 0 {
		panic("BUG: assigning 0 IPs?")
	}
	if params.SecondaryPrivateIpAddressCount != nil {
		panic("fakeEC2 doesn't support AWS IPAM")
	}

	// Find the ENI.
	ENI := f.ENIsByID[*params.NetworkInterfaceId]
	for _, newAddr := range params.PrivateIpAddresses {
		for _, addr := range ENI.PrivateIpAddresses {
			if *addr.PrivateIpAddress == newAddr {
				return nil, errBadParam("AssignPrivateIpAddresses", "Address.AlreadyAssigned")
			}
		}
	}

	if f.IgnoreNextAssignPrivateIpAddresses {
		logrus.Warn("FakeEC2: ignoring AssignPrivateIpAddresses but returning success!")
		f.IgnoreNextAssignPrivateIpAddresses = false
		return &ec2.AssignPrivateIpAddressesOutput{
			// Not currently used so not bothering to fill in
		}, nil
	}

	for _, newAddr := range params.PrivateIpAddresses {
		ENI.PrivateIpAddresses = append(ENI.PrivateIpAddresses, types.NetworkInterfacePrivateIpAddress{
			Primary:          boolPtr(false),
			PrivateIpAddress: stringPtr(newAddr),
		})
	}
	f.ENIsByID[*params.NetworkInterfaceId] = ENI

	for ENIID, ENI := range f.ENIsByID {
		if ENIID == *params.NetworkInterfaceId {
			continue
		}
		for _, newAddr := range params.PrivateIpAddresses {
			for i, addr := range ENI.PrivateIpAddresses {
				if *addr.PrivateIpAddress == newAddr {
					// Other ENI has this IP, delete it.
					ENI.PrivateIpAddresses[i] = ENI.PrivateIpAddresses[len(ENI.PrivateIpAddresses)-1]
					ENI.PrivateIpAddresses = ENI.PrivateIpAddresses[:len(ENI.PrivateIpAddresses)-1]
				}
			}
		}
		f.ENIsByID[ENIID] = ENI
	}

	return &ec2.AssignPrivateIpAddressesOutput{
		// Not currently used so not bothering to fill in
	}, nil
}

func (f *fakeEC2) UnassignPrivateIpAddresses(ctx context.Context, params *ec2.UnassignPrivateIpAddressesInput, optFns ...func(*ec2.Options)) (*ec2.UnassignPrivateIpAddressesOutput, error) {
	f.lock.Lock()
	defer f.lock.Unlock()

	if err := f.Errors.NextErrorByCaller(); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(optFns) > 0 {
		panic("fakeEC2 doesn't understand opts")
	}

	if params.NetworkInterfaceId == nil {
		return nil, errBadParam("UnassignPrivateIpAddresses", "NetworkInterfaceId.Missing")
	}

	if len(params.PrivateIpAddresses) == 0 {
		panic("BUG: releasing 0 IPs?")
	}

	// Find the ENI.
	eni, ok := f.ENIsByID[*params.NetworkInterfaceId]
	if !ok {
		return nil, errNotFound("UnassignPrivateIpAddresses", "ENI.NotFound")
	}

	if f.IgnoreNextUnassignPrivateIpAddresses {
		logrus.Warn("FakeEC2: ignoring UnassignPrivateIpAddresses but returning success!")
		f.IgnoreNextUnassignPrivateIpAddresses = false
		return &ec2.UnassignPrivateIpAddressesOutput{
			// Not currently used so not bothering to fill in
		}, nil
	}

	for _, newAddr := range params.PrivateIpAddresses {
		var updatedAddrs []types.NetworkInterfacePrivateIpAddress
		found := false
		for _, addr := range eni.PrivateIpAddresses {
			if *addr.PrivateIpAddress == newAddr {
				if addr.Primary != nil && *addr.Primary {
					return nil, errBadParam("UnassignPrivateIpAddresses", "NetworkInterfaceId.Primary")
				}
				found = true
				continue
			}
			updatedAddrs = append(updatedAddrs, addr)
		}
		if !found {
			return nil, errNotFound("UnassignPrivateIpAddresses", "Address.NotFound")
		}
		eni.PrivateIpAddresses = updatedAddrs
	}

	f.ENIsByID[*params.NetworkInterfaceId] = eni

	return &ec2.UnassignPrivateIpAddressesOutput{
		// Not currently used so not bothering to fill in
	}, nil
}

func (f *fakeEC2) DeleteNetworkInterface(ctx context.Context, params *ec2.DeleteNetworkInterfaceInput, optFns ...func(*ec2.Options)) (*ec2.DeleteNetworkInterfaceOutput, error) {
	f.lock.Lock()
	defer f.lock.Unlock()

	if err := f.Errors.NextErrorByCaller(); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(optFns) > 0 {
		panic("fakeEC2 doesn't understand opts")
	}

	if params.NetworkInterfaceId == nil {
		panic("BUG: caller should supply network interface ID")
	}

	ENI, ok := f.ENIsByID[*params.NetworkInterfaceId]
	if !ok {
		return nil, errNotFound("DeleteNetworkInterface", "NetworkInterfaceId.NotFound")
	}

	if ENI.Status != types.NetworkInterfaceStatusAvailable {
		return nil, errBadParam("DeleteNetworkInterface", "NetworkInterface.IsAttached")
	}

	delete(f.ENIsByID, *params.NetworkInterfaceId)
	return &ec2.DeleteNetworkInterfaceOutput{ /* not used by caller */ }, nil
}

func (f *fakeEC2) AssociateAddress(ctx context.Context, params *ec2.AssociateAddressInput, optFns ...func(*ec2.Options)) (*ec2.AssociateAddressOutput, error) {
	f.lock.Lock()
	defer f.lock.Unlock()

	if err := f.Errors.NextErrorByCaller(); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(optFns) > 0 {
		panic("fakeEC2 doesn't understand opts")
	}

	// Check inputs are things we support.
	if params.DryRun != nil {
		panic("fakeEC2 doesn't support requested feature")
	}
	if params.AllocationId == nil {
		panic("fakeEC2 requires AllocationId")
	}
	if params.PublicIp != nil {
		panic("fakeEC2 doesn't support PublicIp")
	}
	if params.NetworkInterfaceId == nil {
		panic("BUG: expecting NetworkInterfaceId to be set")
	}
	if params.PrivateIpAddress == nil {
		panic("BUG: expecting PrivateIpAddress to be set")
	}
	if params.AllowReassociation == nil || *params.AllowReassociation != false {
		panic("BUG: expecting AllowReassociation to be false")
	}

	// Look up the elastic IP.
	eip, ok := f.ElasticIPsByID[*params.AllocationId]
	if !ok {
		return nil, errNotFound("AssociateAddress", "ElasticIP.NotFound" /* Made up */)
	}
	if eip.AssociationId != nil {
		f.alreadyAssocTriggered = true
		return nil, errBadParam("AssociateAddress", "Resource.AlreadyAssociated" /* Real/expected error code */)
	}

	// Look up the ENI.
	eni, ok := f.ENIsByID[*params.NetworkInterfaceId]
	if !ok {
		return nil, errNotFound("AssociateAddress", "ENI.NotFound" /* Made up */)
	}
	found := false
	var assocID string
	for i, privIP := range eni.PrivateIpAddresses {
		if *privIP.PrivateIpAddress == *params.PrivateIpAddress {
			// Found the right IP.
			found = true
			if privIP.Association != nil {
				return nil, errBadParam("AssociateAddress", "IP.AlreadyAssociated" /* made up */)
			}
			assocID = f.nextEIPAssocID()
			privIP.Association = &types.NetworkInterfaceAssociation{
				AllocationId:  eip.AllocationId,
				AssociationId: &assocID,
				PublicIp:      eip.PublicIp,
			}
			eni.PrivateIpAddresses[i] = privIP
			f.ENIsByID[*params.NetworkInterfaceId] = eni
			eip.AssociationId = &assocID
			eip.PrivateIpAddress = privIP.PrivateIpAddress
			eip.NetworkInterfaceId = eni.NetworkInterfaceId
			break
		}
	}
	if !found {
		return nil, errNotFound("AssociateAddress", "PrivateIP.NotFound" /* Made up */)
	}

	return &ec2.AssociateAddressOutput{
		AssociationId: &assocID,
	}, nil
}

func (f *fakeEC2) DisassociateAddress(ctx context.Context, params *ec2.DisassociateAddressInput, optFns ...func(*ec2.Options)) (*ec2.DisassociateAddressOutput, error) {
	f.lock.Lock()
	defer f.lock.Unlock()

	if err := f.Errors.NextErrorByCaller(); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(optFns) > 0 {
		panic("fakeEC2 doesn't understand opts")
	}

	// Check inputs are things we support.
	if params.DryRun != nil {
		panic("fakeEC2 doesn't support requested feature")
	}
	if params.AssociationId == nil {
		panic("fakeEC2 requires AssociationId")
	}
	if params.PublicIp != nil {
		panic("fakeEC2 doesn't support PublicIp")
	}

	// Look up the elastic IP.
	var eip *types.Address
	found := false
	for _, eip = range f.ElasticIPsByID {
		if eip.AssociationId != nil && *eip.AssociationId == *params.AssociationId {
			found = true
			break
		}
	}
	if !found {
		return nil, errNotFound("DisassociateAddress", "Resource.NotFound" /* Made up */)
	}

	// Look up the ENI.
	eni, ok := f.ENIsByID[*eip.NetworkInterfaceId]
	if !ok {
		panic("BUG: EIP attached to non-existent ENI?")
	}
	found = false
	for i, privIP := range eni.PrivateIpAddresses {
		if *privIP.PrivateIpAddress == *eip.PrivateIpAddress {
			// Found the right IP.
			found = true
			privIP.Association = nil
			eni.PrivateIpAddresses[i] = privIP
			f.ENIsByID[*eni.NetworkInterfaceId] = eni
			break
		}
	}
	if !found {
		panic("BUG: EIP attached to non-existent private IP?")
	}

	eip.AssociationId = nil
	eip.PrivateIpAddress = nil
	eip.NetworkInterfaceId = nil

	return &ec2.DisassociateAddressOutput{}, nil
}

func (f *fakeEC2) DescribeAddresses(ctx context.Context, params *ec2.DescribeAddressesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
	f.lock.Lock()

	defer func(fns []func()) {
		for _, fn := range fns {
			fn()
		}
	}(f.postDescribeAddressesActions)
	f.postDescribeAddressesActions = nil

	defer f.lock.Unlock()

	if err := f.Errors.NextErrorByCaller(); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(optFns) > 0 {
		panic("fakeEC2 doesn't understand opts")
	}

	if params.DryRun != nil || params.PublicIps != nil || params.AllocationIds != nil {
		panic("fakeEC2 doesn't support requested feature")
	}

	if len(params.Filters) > 200 {
		panic("BUG: client shouldn't send >200 filters") // AWS hard limit.
	}

	var elasticIPs []types.Address
	for _, eip := range f.ElasticIPsByID {
		allFiltersMatch := true
		for _, filter := range params.Filters {
			filterMatches := false
			switch *filter.Name {
			case "public-ip":
				for _, v := range filter.Values {
					if *eip.PublicIp == v {
						filterMatches = true
					}
				}
			default:
				panic("fakeEC2 doesn't understand filter " + *filter.Name)
			}
			allFiltersMatch = allFiltersMatch && filterMatches
		}
		if !allFiltersMatch {
			continue
		}

		// ENI matches
		elasticIPs = append(elasticIPs, *eip)
	}

	// DescribeNetworkInterfaces seems to return an empty list rather than a not-found error.
	return &ec2.DescribeAddressesOutput{
		Addresses: elasticIPs,
	}, nil
}

func (f *fakeEC2) NumENIs() int {
	f.lock.Lock()
	defer f.lock.Unlock()

	return len(f.ENIsByID)
}

func (f *fakeEC2) GetENI(eniid string) types.NetworkInterface {
	f.lock.Lock()
	defer f.lock.Unlock()

	return f.ENIsByID[eniid]
}

func (f *fakeEC2) GetElasticIPByPrivateIP(privateIP string) string {
	f.lock.Lock()
	defer f.lock.Unlock()

	privIPAsCIDR := ip.MustParseCIDROrIP(privateIP)
	for _, eni := range f.ENIsByID {
		for _, pia := range eni.PrivateIpAddresses {
			if ip.MustParseCIDROrIP(safeReadString(pia.PrivateIpAddress)) == privIPAsCIDR {
				if pia.Association == nil {
					logrus.WithField("privIP", privateIP).Debug("Private IP has no associated public IP")
					return ""
				}
				return *pia.Association.PublicIp
			}
		}
	}
	logrus.WithField("privIP", privateIP).Warn("Private IP not found")
	return ""
}

func (f *fakeEC2) GetElasticIP(eipid string) types.Address {
	f.lock.Lock()
	defer f.lock.Unlock()

	return *f.ElasticIPsByID[eipid]
}

func (f *fakeEC2) SetRemoteEIPAssociation(id string) {
	f.lock.Lock()
	defer f.lock.Unlock()

	f.ElasticIPsByID[id].AssociationId = stringPtr(f.nextEIPAssocID())
}

func (f *fakeEC2) ClearRemoteEIPAssociation(id string) {
	f.lock.Lock()
	defer f.lock.Unlock()

	f.ElasticIPsByID[id].AssociationId = nil
}

func (f *fakeEC2) AddPostDescribeAddressesAction(f2 func()) {
	f.lock.Lock()
	defer f.lock.Unlock()

	f.postDescribeAddressesActions = append(f.postDescribeAddressesActions, f2)
}

func (f *fakeEC2) AlreadyAssociatedTrigerred() bool {
	f.lock.Lock()
	defer f.lock.Unlock()

	return f.alreadyAssocTriggered
}
