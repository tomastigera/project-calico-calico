// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aws

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/clock"

	"github.com/projectcalico/calico/libcalico-go/lib/health"
)

const (
	CalicoTagPrefix                         = "calico:"
	CalicoNetworkInterfaceTagUse            = CalicoTagPrefix + "use"
	CalicoNetworkInterfaceTagOwningInstance = CalicoTagPrefix + "instance"

	CalicoNetworkInterfaceUseSecondary = "secondary"
)

const (
	timeout         = 20 * time.Second
	retries         = 3
	deviceIndexZero = 0
)

func convertError(err error) string {
	var awsErr smithy.APIError
	if errors.As(err, &awsErr) {
		return fmt.Sprintf("%s: %s", awsErr.ErrorCode(), awsErr.ErrorMessage())
	}

	return fmt.Sprintf("%v", err.Error())
}

func retriable(err error) bool {
	var awsErr smithy.APIError
	if errors.As(err, &awsErr) {
		switch awsErr.ErrorCode() {
		case "InternalError":
			return true
		case "InternalFailure":
			return true
		case "RequestLimitExceeded":
			return true
		case "ServiceUnavailable":
			return true
		case "Unavailable":
			return true
		}
	}

	return false
}

type SrcDstCheckUpdater interface {
	Update(option apiv3.AWSSrcDstCheckOption) error
}

func WaitForEC2SrcDstCheckUpdate(check apiv3.AWSSrcDstCheckOption, healthAgg *health.HealthAggregator, updater SrcDstCheckUpdater, c clock.Clock) {
	log.Infof("Setting AWS EC2 source-destination-check to %s", check)

	const (
		initBackoff   = 30 * time.Second
		maxBackoff    = 8 * time.Minute
		resetDuration = time.Hour
		backoffFactor = 2.0
		jitter        = 0.1
	)

	//nolint:staticcheck // Ignore SA1019 deprecated
	backoffMgr := wait.NewExponentialBackoffManager(initBackoff, maxBackoff, resetDuration, backoffFactor, jitter, c)
	defer backoffMgr.Backoff().Stop()

	const healthName = "AWSSourceDestinationCheck"
	healthAgg.RegisterReporter(healthName, &health.HealthReport{Live: true, Ready: true}, 0)

	// set not-ready.
	healthAgg.Report(healthName, &health.HealthReport{Live: true, Ready: false})

	for {
		if err := updater.Update(check); err != nil {
			log.WithField("src-dst-check", check).Warnf("Failed to set source-destination-check: %v", err)
		} else {
			// set ready.
			healthAgg.Report(healthName, &health.HealthReport{Live: true, Ready: true})
			return
		}

		<-backoffMgr.Backoff().C()
	}
}

func PrimaryInterface() (*types.InstanceNetworkInterface, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ec2Cli, err := NewEC2Client(ctx)
	if err != nil {
		return nil, err
	}

	ec2Iface, err := ec2Cli.GetMyPrimaryEC2NetworkInterface(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting ec2 network-interface: %s", convertError(err))
	}

	return ec2Iface, nil
}

type EC2SrcDstCheckUpdater struct{}

func NewEC2SrcDstCheckUpdater() *EC2SrcDstCheckUpdater {
	return &EC2SrcDstCheckUpdater{}
}

func (updater *EC2SrcDstCheckUpdater) Update(caliCheckOption apiv3.AWSSrcDstCheckOption) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ec2Cli, err := NewEC2Client(ctx)
	if err != nil {
		return err
	}

	// We are only modifying network interface with device-id-0 to update
	// instance source-destination-check.
	ec2NetId, err := ec2Cli.GetMyPrimaryEC2NetworkInterfaceID(ctx)
	if err != nil {
		return fmt.Errorf("error getting ec2 network-interface-id: %s", convertError(err))
	}

	checkEnabled := caliCheckOption == apiv3.AWSSrcDstCheckOptionEnable
	err = ec2Cli.SetEC2SourceDestinationCheck(ctx, ec2NetId, checkEnabled)
	if err != nil {
		return fmt.Errorf("error setting src-dst-check for network-interface-id: %s", convertError(err))
	}

	log.Infof("Successfully set source-destination-check to %t on network-interface-id: %s", checkEnabled, ec2NetId)
	return nil
}

// Interface for EC2 Metadata service.
type ec2MetadataAPI interface {
	GetInstanceIdentityDocument(
		ctx context.Context, params *imds.GetInstanceIdentityDocumentInput, optFns ...func(*imds.Options),
	) (*imds.GetInstanceIdentityDocumentOutput, error)
	GetRegion(
		ctx context.Context, params *imds.GetRegionInput, optFns ...func(*imds.Options),
	) (*imds.GetRegionOutput, error)
}

type ec2API interface {
	DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	ModifyNetworkInterfaceAttribute(ctx context.Context, params *ec2.ModifyNetworkInterfaceAttributeInput, optFns ...func(*ec2.Options)) (*ec2.ModifyNetworkInterfaceAttributeOutput, error)
	DescribeSubnets(ctx context.Context, params *ec2.DescribeSubnetsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error)
	DescribeInstanceTypes(ctx context.Context, params *ec2.DescribeInstanceTypesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstanceTypesOutput, error)
	DescribeNetworkInterfaces(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
	CreateNetworkInterface(ctx context.Context, params *ec2.CreateNetworkInterfaceInput, optFns ...func(*ec2.Options)) (*ec2.CreateNetworkInterfaceOutput, error)
	AttachNetworkInterface(ctx context.Context, params *ec2.AttachNetworkInterfaceInput, optFns ...func(*ec2.Options)) (*ec2.AttachNetworkInterfaceOutput, error)
	AssignPrivateIpAddresses(ctx context.Context, params *ec2.AssignPrivateIpAddressesInput, optFns ...func(*ec2.Options)) (*ec2.AssignPrivateIpAddressesOutput, error)
	UnassignPrivateIpAddresses(ctx context.Context, params *ec2.UnassignPrivateIpAddressesInput, optFns ...func(*ec2.Options)) (*ec2.UnassignPrivateIpAddressesOutput, error)
	DetachNetworkInterface(ctx context.Context, params *ec2.DetachNetworkInterfaceInput, optFns ...func(*ec2.Options)) (*ec2.DetachNetworkInterfaceOutput, error)
	DeleteNetworkInterface(ctx context.Context, params *ec2.DeleteNetworkInterfaceInput, optFns ...func(*ec2.Options)) (*ec2.DeleteNetworkInterfaceOutput, error)

	AssociateAddress(ctx context.Context, params *ec2.AssociateAddressInput, optFns ...func(*ec2.Options)) (*ec2.AssociateAddressOutput, error)
	DisassociateAddress(ctx context.Context, params *ec2.DisassociateAddressInput, optFns ...func(*ec2.Options)) (*ec2.DisassociateAddressOutput, error)
	DescribeAddresses(ctx context.Context, params *ec2.DescribeAddressesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error)
}

func getEC2InstanceID(ctx context.Context, svc ec2MetadataAPI) (string, error) {
	idDoc, err := svc.GetInstanceIdentityDocument(ctx, nil)
	if err != nil {
		return "", err
	}
	log.Debugf("ec2-instance-id: %s", idDoc.InstanceID)
	return idDoc.InstanceID, nil
}

func getEC2Region(ctx context.Context, svc ec2MetadataAPI) (string, error) {
	region, err := svc.GetRegion(ctx, nil)
	if err != nil {
		return "", err
	}
	log.Debugf("region: %s", region)
	return region.Region, nil
}

type EC2Client struct {
	EC2Svc     ec2API
	InstanceID string
}

func NewEC2Client(ctx context.Context) (*EC2Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("error loading AWS config: %w", err)
	}
	metadataSvc := imds.NewFromConfig(cfg)

	region, err := getEC2Region(ctx, metadataSvc)
	if err != nil {
		return nil, fmt.Errorf("error getting ec2 region: %s", convertError(err))
	}

	instanceId, err := getEC2InstanceID(ctx, metadataSvc)
	if err != nil {
		return nil, fmt.Errorf("error getting ec2 instance-id: %s", convertError(err))
	}

	ec2Svc := ec2.NewFromConfig(cfg, func(o *ec2.Options) {
		o.Region = region
	})
	if ec2Svc == nil {
		return nil, fmt.Errorf("error connecting to EC2 service")
	}

	return &EC2Client{
		EC2Svc:     ec2Svc,
		InstanceID: instanceId,
	}, nil
}

var ErrNotFound = errors.New("resource not found")

func (c *EC2Client) GetMyInstance(ctx context.Context) (instance *types.Instance, err error) {
	input := &ec2.DescribeInstancesInput{
		InstanceIds: []string{
			c.InstanceID,
		},
	}

	var out *ec2.DescribeInstancesOutput
	for range retries {
		out, err = c.EC2Svc.DescribeInstances(ctx, input)
		if err != nil {
			if retriable(err) {
				// if error is temporary, try again in a second.
				time.Sleep(1 * time.Second)
				log.WithField("instance-id", c.InstanceID).Debug("retrying getting network-interface-id")
				continue
			}
		}
		break
	}

	if err != nil {
		return nil, fmt.Errorf("failed to retrieve AWS instance %s: %w", c.InstanceID, err)
	}

	// Instances are grouped by "Reservation", which is the original request to create a particular set of instances.
	// Seems likely that at most one instance can be returned here.  Not clear if the reservation would include
	// any other instances that were created at the same time but it's easy to be defensive by looping over both.
	for _, resv := range out.Reservations {
		for _, instance := range resv.Instances {
			if instance.InstanceId == nil || *instance.InstanceId != c.InstanceID {
				// A reservation can contain more than one instance. Not clear if more than one can be returned here
				// but be defensive.
				continue
			}
			// Found our instance.
			return &instance, nil
		}
	}
	return nil, fmt.Errorf("no returned results matched ID %s: %w",
		c.InstanceID, ErrNotFound)
}

func (c *EC2Client) GetAZLocalSubnets(ctx context.Context) ([]types.Subnet, error) {
	inst, err := c.GetMyInstance(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get my instance: %w", err)
	}
	if inst.Placement == nil || inst.Placement.AvailabilityZone == nil || inst.VpcId == nil {
		return nil, fmt.Errorf("AWS instance missing placement information: %v", inst)
	}
	dso, err := c.EC2Svc.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("availability-zone"),
				Values: []string{*inst.Placement.AvailabilityZone},
			},
			{
				Name:   aws.String("vpc-id"),
				Values: []string{*inst.VpcId},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list subnets: %w", err)
	}
	return dso.Subnets, nil
}

func (c *EC2Client) GetMyInstanceType(ctx context.Context) (*types.InstanceTypeInfo, error) {
	inst, err := c.GetMyInstance(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get my instance: %w", err)
	}
	ito, err := c.EC2Svc.DescribeInstanceTypes(ctx, &ec2.DescribeInstanceTypesInput{
		InstanceTypes: []types.InstanceType{inst.InstanceType},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve instance type %v: %w", inst.InstanceType, err)
	}
	for _, it := range ito.InstanceTypes {
		if it.InstanceType == inst.InstanceType {
			return &it, nil
		}
	}
	return nil, fmt.Errorf("failed to retrieve instance type %v: query returned no results",
		inst.InstanceType)
}

type NetworkCapabilities struct {
	MaxNetworkInterfaces int
	NetworkCards         []types.NetworkCardInfo
	MaxIPv4PerInterface  int
	MaxIPv6PerInterface  int
}

func (n NetworkCapabilities) MaxENIsForCard(idx int) int {
	if idx >= len(n.NetworkCards) { // defensive; would be an AWS bug.
		log.Warn("Asked about network card that doesn't exist, returning 0.")
		return 0
	}
	maxPtr := n.NetworkCards[idx].MaximumNetworkInterfaces
	if maxPtr == nil { // defensive; would be an AWS bug.
		log.Error("AWS failed to return maximum network interfaces value on query.")
		return 0
	}
	return int(*maxPtr)
}

func (c *EC2Client) GetMyNetworkCapabilities(ctx context.Context) (netc NetworkCapabilities, err error) {
	instType, err := c.GetMyInstanceType(ctx)
	if err != nil {
		return
	}
	return InstanceTypeNetworkCapabilities(instType)
}

func InstanceTypeNetworkCapabilities(instType *types.InstanceTypeInfo) (netc NetworkCapabilities, err error) {
	netInfo := instType.NetworkInfo
	if netInfo == nil {
		err = fmt.Errorf("instance type missing network info")
		return
	}
	if netInfo.MaximumNetworkInterfaces == nil ||
		netInfo.Ipv4AddressesPerInterface == nil {
		err = fmt.Errorf("instance type missing values: %v", netInfo)
	}
	netc.MaxNetworkInterfaces = int(*netInfo.MaximumNetworkInterfaces)
	netc.MaxIPv4PerInterface = int(*netInfo.Ipv4AddressesPerInterface)
	if netInfo.Ipv6Supported != nil && *netInfo.Ipv6Supported {
		if netInfo.Ipv6AddressesPerInterface != nil {
			netc.MaxIPv6PerInterface = int(*netInfo.Ipv6AddressesPerInterface)
		}
	}
	netc.NetworkCards = netInfo.NetworkCards
	return
}

func (c *EC2Client) GetMyEC2NetworkInterfaces(ctx context.Context) ([]types.NetworkInterface, error) {
	// We use DescribeNetworkInterfaces rather than retrieving the list attached to the Instance so that we can
	// see the tags.
	nio, err := c.EC2Svc.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("attachment.instance-id"),
				Values: []string{c.InstanceID},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list attached network interfaces: %w", err)
	}
	return nio.NetworkInterfaces, nil
}

func (c *EC2Client) GetMyPrimaryEC2NetworkInterface(ctx context.Context) (*types.InstanceNetworkInterface, error) {
	var err error

	input := &ec2.DescribeInstancesInput{
		InstanceIds: []string{
			c.InstanceID,
		},
	}

	var out *ec2.DescribeInstancesOutput
	for range retries {
		out, err = c.EC2Svc.DescribeInstances(ctx, input)
		if err != nil {
			if retriable(err) {
				// if error is temporary, try again in a second.
				time.Sleep(1 * time.Second)
				log.WithField("instance-id", c.InstanceID).Debug("retrying getting network-interface")
				continue
			}
			return nil, err
		} else {
			break
		}
	}

	if out == nil || len(out.Reservations) == 0 {
		return nil, fmt.Errorf("no network-interface found for EC2 instance %s", c.InstanceID)
	}

	var interfaceId string
	for _, instance := range out.Reservations[0].Instances {
		if len(instance.NetworkInterfaces) == 0 {
			return nil, fmt.Errorf("no network-interface found for EC2 instance %s", c.InstanceID)
		}
		// An instance can have multiple interfaces and the API response can be
		// out-of-order interface list. We compare the device-id in the
		// response to make sure we get the right device.
		for _, networkInterface := range instance.NetworkInterfaces {
			if networkInterface.Attachment != nil &&
				networkInterface.Attachment.DeviceIndex != nil &&
				*(networkInterface.Attachment.DeviceIndex) == deviceIndexZero {
				return &networkInterface, nil
			}
			log.Debugf("instance-id: %s, network-interface-id: %s", c.InstanceID, interfaceId)
		}
	}

	return nil, fmt.Errorf("no primary network-interface found for EC2 instance %s", c.InstanceID)
}

func (c *EC2Client) GetMyPrimaryEC2NetworkInterfaceID(ctx context.Context) (networkInstanceId string, err error) {
	instance, err := c.GetMyInstance(ctx)
	if err != nil {
		return "", err
	}

	if len(instance.NetworkInterfaces) == 0 {
		return "", fmt.Errorf("no network-interface-id found for EC2 instance %s", c.InstanceID)
	}

	// An instance can have more than one interface.  By definition, the "primary" interface has
	// DeviceIndex equal to 0.
	for _, networkInterface := range instance.NetworkInterfaces {
		if networkInterface.Attachment != nil &&
			networkInterface.Attachment.DeviceIndex != nil &&
			*(networkInterface.Attachment.DeviceIndex) == deviceIndexZero {
			interfaceId := *(networkInterface.NetworkInterfaceId)
			if interfaceId != "" {
				log.Debugf("Found device-0: instance-id: %s, network-interface-id: %s", c.InstanceID, interfaceId)
				return interfaceId, nil
			}
		}
	}
	return "", fmt.Errorf("no network-interface-id found for EC2 instance %s", c.InstanceID)
}

func (c *EC2Client) SetEC2SourceDestinationCheck(ctx context.Context, ec2NetId string, checkVal bool) error {
	input := &ec2.ModifyNetworkInterfaceAttributeInput{
		NetworkInterfaceId: aws.String(ec2NetId),
		SourceDestCheck: &types.AttributeBooleanValue{
			Value: aws.Bool(checkVal),
		},
	}

	var err error
	for range retries {
		_, err = c.EC2Svc.ModifyNetworkInterfaceAttribute(ctx, input)
		if err != nil {
			if retriable(err) {
				// if error is temporary, try again in a second.
				time.Sleep(1 * time.Second)
				log.WithField("net-instance-id", ec2NetId).Debug("retrying setting source-destination-check")
				continue
			}

			return err
		} else {
			break
		}
	}

	return err
}

func NetworkInterfaceIsCalicoSecondary(nic types.NetworkInterface) bool {
	v, _ := LookupTag(nic.TagSet, CalicoNetworkInterfaceTagUse)
	return v == CalicoNetworkInterfaceUseSecondary
}

func LookupTag(tags []types.Tag, key string) (value string, found bool) {
	for _, t := range tags {
		if t.Key != nil && *t.Key == key {
			found = true
			if t.Value != nil {
				value = *t.Value
			}
			return
		}
	}
	return
}
