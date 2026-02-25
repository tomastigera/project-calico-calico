package fortimanager

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	FortiGateIpMaskType = "ipmask"
	FortiGateSdnType    = "sdn"
	FortiMgrIpMaskType  = 0
)

type FortiManagerClient struct {
	Name     string
	Ip       string
	Username string
	Password string
	Adom     string
	Client   FortiManagerRestClient
}

type SessionManager interface {
	SetSession(string)
}

type FortiGateClient struct {
	Name        string
	Adom        string
	Ip          string
	AccessToken string
	Client      FortiGateRestClientApi
	Vdom        string
}

func NewFortiGateClient(name, ip, accessToken, vdom string, fg FortiGateRestClientApi) FortiFWClientApi {
	return &FortiGateClient{
		Name:        name,
		Adom:        "",
		Ip:          ip,
		AccessToken: accessToken,
		Client:      fg,
		Vdom:        vdom,
	}
}

func NewFortiManagerClient(name, ip, username, password, adom string, insecureSkipVerify bool) (FortiFWClientApi, error) {
	fmc := &FortiManagerClient{
		Ip:       ip,
		Username: username,
		Password: password,
		Adom:     adom,
		Name:     name,
		Client: FortiManagerRestClient{
			name:               "Init Client",
			URL:                fmt.Sprintf("https://%s/jsonrpc", ip),
			inSecureSkipVerify: insecureSkipVerify,
		},
	}
	if ok := fmc.Login(); ok != nil {
		return nil, ok
	}
	return fmc, nil
}

type FortiFWClientApi interface {
	CreateFirewallAddress(FortiFWAddress) error
	UpdateFirewallAddress(FortiFWAddress) error
	DeleteFirewallAddress(FortiFWAddress) error
	ListAllFirewallAddresses() ([]FortiFWAddress, error)
	GetFirewallAddress(string) (FortiFWAddress, error)
	ListAllFirewallAddressGroups() ([]FortiFWAddressGroup, error)
	GetFirewallAddressGroup(string) (FortiFWAddressGroup, error)
	UpdateFirewallAddressGroup(FortiFWAddressGroup) error
	CreateFirewallAddressGroup(FortiFWAddressGroup) error
	DeleteFirewallAddressGroup(string) error
	GetFirewallPolicyPackage(string) error
	ListAllFirewallRulesInPkg(string) ([]FortiFWPolicy, error)
}

// Create a Firewall Address object in FortiGate device
// http POST request to FortiGate device
func (f *FortiGateClient) CreateFirewallAddress(fortiFWAddr FortiFWAddress) error {

	//Copy data from Common FW object to FortiGate Specific
	fwAddrObj := RespFortiGateFWAddressData{
		Name:    fortiFWAddr.Name,
		Comment: fortiFWAddr.Comment,
		Type:    fortiFWAddr.Type,
		SubType: fortiFWAddr.SubType,
		Subnet:  fmt.Sprintf("%s %s", fortiFWAddr.IpAddr, fortiFWAddr.Mask),
	}

	//create a URL string for HTTP POST
	url := f.URL("/api/v2/cmdb/firewall/address")

	//Marshal data
	bytesRepresentation, err := json.Marshal(fwAddrObj)
	if err != nil {
		log.WithError(err).Error("Json Marshal Error")
		return ErrorClientMarshallingData{Err: err, Identifier: ""}
	}
	var res RespFortiGateStatus
	//http POST request to FortiGate Device
	b, err := f.Client.FortiGateRestPost(url, bytesRepresentation)
	if err != nil {
		log.Error("Unable to do http-Post with FortiGate device")
		return ErrorUnknownConnectionIssue{Err: err}
	}
	//UnMarshal data
	err = json.Unmarshal(b, &res)
	if err != nil {
		log.WithError(err).Error("Json UnMarshal Error")
		return ErrorClientMarshallingData{Err: err, Identifier: "Un"}
	}
	//handle errors returned by fortigate API, these errors are in the payload of response
	if res.HttpStatus != FortiGateReturnSuccess {
		switch code := res.HttpStatus; code {
		case FortiGateResourceNotFound:
			tempStr := fmt.Sprintf("FwAddress :%s in Fortigate(%s)", fwAddrObj.Name, f.Ip)
			return ErrorResourceDoesNotExist{Identifier: tempStr, Err: errors.New("unable to find the specified object")}
		default:
			return fmt.Errorf("unhandled error code %v status %v", code, res.Status)
		}
	}

	return nil
}

// Update the Firewall Address
func (f *FortiGateClient) UpdateFirewallAddress(fortiFWAddr FortiFWAddress) error {

	//Copy data from generic FW object to FortiGate Specific
	fwAddrObj := RespFortiGateFWAddressData{
		Name:    fortiFWAddr.Name,
		Comment: fortiFWAddr.Comment,
		Type:    fortiFWAddr.Type,
		SubType: fortiFWAddr.SubType,
		Subnet:  fmt.Sprintf("%s %s", fortiFWAddr.IpAddr, fortiFWAddr.Mask),
	}

	//create a URL string for HTTP PUT request
	url := f.URL(fmt.Sprintf("/api/v2/cmdb/firewall/address/%s", fortiFWAddr.Name))

	//Marshal data
	bytesRepresentation, err := json.Marshal(fwAddrObj)
	if err != nil {
		log.WithError(err).Error("Json Marshal Error")
		return ErrorClientMarshallingData{Err: err, Identifier: ""}
	}
	var res RespFortiGateStatus
	//http PUT  request to FortiGate Device
	b, err := f.Client.FortiGateRestPut(url, bytesRepresentation)
	if err != nil {
		log.Error("Unable to do http-Put with FortiGate device")
		return ErrorUnknownConnectionIssue{Err: err}
	}
	//UnMarshal data
	err = json.Unmarshal(b, &res)
	if err != nil {
		log.WithError(err).Error("Json UnMarshal Error")
		return ErrorClientMarshallingData{Err: err, Identifier: "Un"}
	}

	//handle errors returned by fortigate API, these errors are in the payload of response
	if res.HttpStatus != FortiGateReturnSuccess {
		switch res.HttpStatus {
		case FortiGateResourceNotFound:
			tempStr := fmt.Sprintf("FwAddress :%s in Fortigate(%s)", fortiFWAddr.Name, f.Ip)
			return ErrorResourceDoesNotExist{Identifier: tempStr, Err: errors.New("unable to find the specified object")}
		default:
			return fmt.Errorf("unhandled error code %v status %v", res.HttpStatus, res.Status)
		}
	}

	return nil
}

// Delete the Firewall Address in FortiGate device
func (f *FortiGateClient) DeleteFirewallAddress(fortiFWAddr FortiFWAddress) error {
	//create a URL string for delete request
	url := f.URL(fmt.Sprintf("/api/v2/cmdb/firewall/address/%s", fortiFWAddr.Name))

	//http Delete  request to FortiGate Device
	b, err := f.Client.FortiGateRestDelete(url)
	if err != nil {
		log.Error("Unable to do http-Delete with FortiGate device")
		return ErrorUnknownConnectionIssue{Err: err}
	}

	var res RespFortiGateStatus
	//UnMarshal data
	err = json.Unmarshal(b, &res)
	if err != nil {
		log.WithError(err).Error("Json UnMarshal Error")
		return ErrorClientMarshallingData{Err: err, Identifier: "Un"}
	}

	//handle errors returned by fortigate API, these errors are in the payload of response
	if res.HttpStatus != FortiGateReturnSuccess {
		switch res.HttpStatus {
		case FortiGateResourceNotFound:
			tempStr := fmt.Sprintf("FwAddress :%s in Fortigate(%s)", fortiFWAddr.Name, f.Ip)
			return ErrorResourceDoesNotExist{Identifier: tempStr, Err: errors.New("unable to find the specified object")}
		default:
			return fmt.Errorf("unhandled error code %v status %v", res.HttpStatus, res.Status)
		}
	}

	return nil
}

// Get all Firewall Addresses in FortiGate
func (f *FortiGateClient) ListAllFirewallAddresses() ([]FortiFWAddress, error) {
	//create a URL string for Getting all FW addresses
	url := f.URL("/api/v2/cmdb/firewall/address")

	fwAddressObjs := []FortiFWAddress{}
	//http GET request to FortiGate Device
	b, err := f.Client.FortiGateRestGet(url)
	if err != nil {
		log.Error("Unable to do http-Get with FortiGate device")
		return fwAddressObjs, ErrorUnknownConnectionIssue{Err: err}
	}
	var res RespFortiGateAddress
	//UnMarshal data
	err = json.Unmarshal(b, &res)
	if err != nil {
		log.WithError(err).Error("Json UnMarshal Error")
		return fwAddressObjs, ErrorClientMarshallingData{Err: err, Identifier: "Un"}
	}

	if res.HttpStatus != FortiGateReturnSuccess {
		return fwAddressObjs, fmt.Errorf("error when listing firewall addresses %v", err)
	}
	//Convert return data to FortiFwAddress format
	for _, result := range res.Result {
		//Pass Non-IP based Addresses
		//Address objects created by Firewall Controller is only IPMASK type
		//other Address objects aren't handled gracefully.THis will end up
		//logging lot false positives.
		if result.Type != FortiGateIpMaskType {
			continue
		}
		subnetParts := strings.Fields(result.Subnet)
		ip := ""
		mask := ""
		if len(subnetParts) == 2 {
			ip = subnetParts[0]
			mask = subnetParts[1]
		} else {
			log.WithFields(log.Fields{
				"subnet":       result.Subnet,
				"subnetLength": len(subnetParts),
			}).Error("FortiGate Firewall Address subnet value incorrect values.")
		}
		fwAddr := FortiFWAddress{
			Comment: result.Comment,
			Name:    result.Name,
			IpAddr:  ip,
			Mask:    mask,
			SubType: result.SubType,
			Type:    result.Type,
		}
		fwAddressObjs = append(fwAddressObjs, fwAddr)
	}
	return fwAddressObjs, nil
}

// Get the Firewall Address object from FortiGate
func (f *FortiGateClient) GetFirewallAddress(fwAddr string) (FortiFWAddress, error) {
	//create a URL string for getting the FW address object
	url := f.URL(fmt.Sprintf("/api/v2/cmdb/firewall/address/%s", fwAddr))

	var fwAddressObj FortiFWAddress

	//http GET request to FortiGate Device
	b, err := f.Client.FortiGateRestGet(url)
	if err != nil {
		log.Error("Unable to do http-Get with FortiGate device")
		return fwAddressObj, ErrorUnknownConnectionIssue{Err: err}
	}
	var res RespFortiGateAddress
	//UnMarshal data
	err = json.Unmarshal(b, &res)
	if err != nil {
		log.WithError(err).Error("Json UnMarshal Error")
		return fwAddressObj, ErrorClientMarshallingData{Err: err, Identifier: "Un"}
	}

	//handle errors returned by fortigate API, these errors are in the payload of response
	if res.HttpStatus != FortiGateReturnSuccess {
		switch code := res.HttpStatus; code {
		case FortiGateResourceNotFound:
			tempStr := fmt.Sprintf("FwAddress :%s in Fortigate(%s)", fwAddr, f.Ip)
			return fwAddressObj, ErrorResourceDoesNotExist{Identifier: tempStr, Err: errors.New("unable to find the specified object")}
		default:
			return fwAddressObj, fmt.Errorf("unhandled error code %v status %v", code, res.Status)
		}
	}
	//Convert return data to FortiFwAddress format
	subnetParts := strings.Fields(res.Result[0].Subnet)
	ip := ""
	mask := ""
	if len(subnetParts) == 2 {
		ip = subnetParts[0]
		mask = subnetParts[1]
	} else {
		log.WithFields(log.Fields{
			"subnet":       res.Result[0].Subnet,
			"subnetLength": len(subnetParts),
		}).Error("FortiGate Firewall Address subnet value incorrect values.")
		return fwAddressObj, errors.New("incorrect return value from FortiGate")
	}
	fwAddressObj.Comment = res.Result[0].Comment
	fwAddressObj.Name = res.Result[0].Name
	fwAddressObj.SubType = res.Result[0].SubType
	fwAddressObj.Type = res.Result[0].Type
	fwAddressObj.IpAddr = ip
	fwAddressObj.Mask = mask
	return fwAddressObj, nil
}

// Get all Firewall address Groups present in the FortiGate
func (f *FortiGateClient) ListAllFirewallAddressGroups() ([]FortiFWAddressGroup, error) {
	//URL string for getting the FW address Group
	url := f.URL("/api/v2/cmdb/firewall/addrgrp")

	fwAddressGroups := []FortiFWAddressGroup{}
	//http GET request to FortiGate Device
	b, err := f.Client.FortiGateRestGet(url)
	if err != nil {
		log.Error("unable to do http-Get with FortiGate device")
		return fwAddressGroups, ErrorUnknownConnectionIssue{Err: err}
	}
	var res RespFortiGateAddressGrp
	//UnMarshal data
	err = json.Unmarshal(b, &res)
	if err != nil {
		log.WithError(err).Error("Json UnMarshal Error")
		return fwAddressGroups, ErrorClientMarshallingData{Err: err, Identifier: "Un"}
	}

	if res.HttpStatus != FortiGateReturnSuccess {
		return fwAddressGroups, fmt.Errorf("error when fetching firewall addresses %v", err)
	}

	for _, result := range res.Result {
		fwAddrGroup := FortiFWAddressGroup{
			Name:    result.Name,
			Comment: result.Comment,
		}
		for _, member := range result.Member {
			fwAddrGroup.Members = append(fwAddrGroup.Members, member.Name)
		}
		fwAddressGroups = append(fwAddressGroups, fwAddrGroup)
	}
	return fwAddressGroups, nil
}

// Get the Firewall address Group present in the FortiGate
func (f *FortiGateClient) GetFirewallAddressGroup(fwAddr string) (FortiFWAddressGroup, error) {

	//URL string for getting the FW address Group
	url := f.URL(fmt.Sprintf("/api/v2/cmdb/firewall/addrgrp/%s", fwAddr))

	var fwAddresses FortiFWAddressGroup
	//http GET request to FortiGate Device
	b, err := f.Client.FortiGateRestGet(url)
	if err != nil {
		log.Error("Unable to do http-Get with FortiGate device")
		return fwAddresses, ErrorUnknownConnectionIssue{Err: err}
	}

	var res RespFortiGateAddressGrp
	err = json.Unmarshal(b, &res)
	if err != nil {
		log.WithError(err).Error("Json UnMarshal Error")
		return fwAddresses, ErrorClientMarshallingData{Err: err, Identifier: "Un"}
	}

	//handle errors returned by fortigate API, these errors are in the payload of response
	if res.HttpStatus != FortiGateReturnSuccess {
		switch code := res.HttpStatus; code {
		case FortiGateResourceNotFound:
			tempStr := fmt.Sprintf("FwAddressGroup :%s in Fortigate(%s)", fwAddr, f.Ip)
			return fwAddresses, ErrorResourceDoesNotExist{Identifier: tempStr, Err: errors.New("unable to find the specified object")}
		default:
			return fwAddresses, fmt.Errorf("unhandled error code %v status %v", code, res.Status)
		}
	}

	fwAddresses.Name = res.Result[0].Name
	fwAddresses.Comment = res.Result[0].Comment
	for _, member := range res.Result[0].Member {
		fwAddresses.Members = append(fwAddresses.Members, member.Name)
	}
	return fwAddresses, nil
}

// Update the Firewall Address Group
func (f *FortiGateClient) UpdateFirewallAddressGroup(fwAddrGrpObj FortiFWAddressGroup) error {

	//create a URL string for HTTP PUT request
	url := f.URL(fmt.Sprintf("/api/v2/cmdb/firewall/addrgrp/%s", fwAddrGrpObj.Name))
	//Create a payload for http post request
	var req RespFortiGateFWAddressGrpData
	req.Name = fwAddrGrpObj.Name
	req.Comment = fwAddrGrpObj.Comment
	for _, member := range fwAddrGrpObj.Members {
		var temp struct {
			Name string `json:"name"`
		}
		temp.Name = member
		req.Member = append(req.Member, temp)
	}

	//Marshal data
	bytesRepresentation, err := json.Marshal(req)
	if err != nil {
		log.WithError(err).Error("Json Marshal Error")
		return ErrorClientMarshallingData{Err: err, Identifier: ""}
	}

	//http PUT  request to FortiGate Device
	b, err := f.Client.FortiGateRestPut(url, bytesRepresentation)
	if err != nil {
		log.Error("Unable to do http-put with FortiGate device")
		return ErrorUnknownConnectionIssue{Err: err}
	}

	var res RespFortiGateAddressGrp
	//UnMarshal data
	err = json.Unmarshal(b, &res)
	if err != nil {
		log.WithError(err).Error("Json UnMarshal Error")
		return ErrorClientMarshallingData{Err: err, Identifier: "Un"}
	}

	//handle errors returned by fortigate API, these errors are in the payload of response
	if res.HttpStatus != FortiGateReturnSuccess {
		switch code := res.HttpStatus; code {
		case FortiGateResourceNotFound:
			tempStr := fmt.Sprintf("FwAddressGroup :%s in Fortigate(%s)", fwAddrGrpObj.Name, f.Ip)
			return ErrorResourceDoesNotExist{Identifier: tempStr, Err: errors.New("unable to find the specified object")}
		default:
			return fmt.Errorf("unhandled error code %v status %v", code, res.Status)
		}
	}

	return nil
}

// Create a Firewall Address Group  in FortiGate device
// http POST request to FortiGate device
func (f *FortiGateClient) CreateFirewallAddressGroup(fwAddrGrp FortiFWAddressGroup) error {

	//create a URL string for HTTP POST
	url := f.URL("/api/v2/cmdb/firewall/addrgrp")

	//Create a payload for http request
	var req RespFortiGateFWAddressGrpData
	req.Name = fwAddrGrp.Name
	req.Comment = fwAddrGrp.Comment
	for _, member := range fwAddrGrp.Members {
		var temp struct {
			Name string `json:"name"`
		}
		temp.Name = member
		req.Member = append(req.Member, temp)
	}

	//Marshal data
	bytesRepresentation, err := json.Marshal(req)
	if err != nil {
		log.WithError(err).Error("Json Marshal Error")
		return ErrorClientMarshallingData{Err: err, Identifier: ""}
	}

	//http POST request to FortiGate Device
	b, err := f.Client.FortiGateRestPost(url, bytesRepresentation)
	if err != nil {
		log.Error("Unable to do http-Post with FortiGate device")
		return ErrorUnknownConnectionIssue{Err: err}
	}

	var res RespFortiGateAddressGrp
	//UnMarshal data
	err = json.Unmarshal(b, &res)
	if err != nil {
		log.WithError(err).Error("Json UnMarshal Error")
		return ErrorClientMarshallingData{Err: err, Identifier: "Un"}
	}

	//handle errors returned by fortigate API, these errors are in the payload of response
	if res.HttpStatus != FortiGateReturnSuccess {
		switch code := res.HttpStatus; code {
		case FortiGateResourceNotFound:
			tempStr := fmt.Sprintf("FwAddressGroup :%s in Fortigate(%s)", fwAddrGrp.Name, f.Ip)
			return ErrorResourceDoesNotExist{Identifier: tempStr, Err: errors.New("unable to find the specified object")}
		default:
			return fmt.Errorf("unhandled error code %v status %v", code, res.Status)
		}
	}

	return nil
}

// Delete the Firewall Address Group in FortiGate device
func (f *FortiGateClient) DeleteFirewallAddressGroup(addrGrpName string) error {
	//create a URL string for delete request
	url := f.URL(fmt.Sprintf("/api/v2/cmdb/firewall/addrgrp/%s", addrGrpName))

	//http Delete  request to FortiGate Device
	b, err := f.Client.FortiGateRestDelete(url)
	if err != nil {
		log.Error("Unable to do http-Delete with FortiGate device")
		return ErrorUnknownConnectionIssue{Err: err}
	}
	var res RespFortiGateStatus
	//UnMarshal data
	err = json.Unmarshal(b, &res)
	if err != nil {
		log.WithError(err).Error("Json UnMarshal Error")
		return ErrorClientMarshallingData{Err: err, Identifier: "Un"}
	}
	//handle errors returned by fortigate API, these errors are in the payload of response
	if res.HttpStatus != FortiGateReturnSuccess {
		switch code := res.HttpStatus; code {
		case FortiGateResourceNotFound:
			tempStr := fmt.Sprintf("FwAddress :%s in Fortigate(%s)", addrGrpName, f.Ip)
			return ErrorResourceDoesNotExist{Identifier: tempStr, Err: errors.New("unable to find the specified object")}
		default:
			return fmt.Errorf("unhandled error code %v status %v", code, res.Status)
		}
	}

	return nil
}

// Get the policy package from FortiManager DB
func (f *FortiGateClient) GetFirewallPolicyPackage(pkgName string) error {
	return nil
}

// Get the policy package from FortiManager DB
func (f *FortiGateClient) ListAllFirewallRulesInPkg(pkgName string) ([]FortiFWPolicy, error) {
	return nil, nil
}

// URL returns a URL as a string with the access token and vdom parameters.
func (f *FortiGateClient) URL(path string) string {
	queryParams := url.Values{}
	queryParams.Set("access_token", f.AccessToken)
	if f.Vdom != "" {
		queryParams.Set("vdom", f.Vdom)
	}
	url := url.URL{
		Scheme:   "https",
		Host:     f.Ip,
		Path:     path,
		RawQuery: queryParams.Encode(),
	}
	return url.String()
}

func (f *FortiManagerClient) fortimanagerRestPost(req SessionManager, resp any, adom string, addrName string) error {

	// If we don't have a session, then try to recreate one.
	if f.Client.session == "" {
		err := f.Login()
		if err != nil {
			log.WithError(err).Error("Login to fortmanager failed")
			return err
		}
	}
	req.SetSession(f.Client.session)

	bytesRepresentation, err := json.Marshal(req)
	if err != nil {
		log.Error("Json Marshal Error : ", err)
		return ErrorClientMarshallingData{Err: err, Identifier: ""}
	}

	b, err := f.Client.Post(bytesRepresentation)
	if err != nil {
		// TODO(doublek): Handle retries for session here.
		log.Error("POST request failed from  FortiManager :", err)
		return ErrorUnknownConnectionIssue{Err: err}
	}

	err = json.Unmarshal(b, resp)
	if err != nil {
		log.Error("Json UnMarshal Error for resp : ", err)
		return ErrorClientMarshallingData{Err: err, Identifier: "Un"}
	}

	var result respLogin
	err = json.Unmarshal(b, &result)
	if err != nil {
		log.Error("Json UnMarshal Error for result: ", err)
		return ErrorClientMarshallingData{Err: err, Identifier: "Un"}
	}
	if result.Result[0].Status.Code != 0 {
		switch code := result.Result[0].Status.Code; code {
		case FortiManagerDuplicateObject:
			tempStr := fmt.Sprintf("(ADOM:%s AddressNme:%s)", adom, addrName)
			return ErrorResourceAlreadyExists{Identifier: tempStr, Err: errors.New(result.Result[0].Status.Message)}
		case FortiManagerObjectNotExist:
			tempStr := fmt.Sprintf("(ADOM:%s AddressName:%s) in FortiManager", adom, addrName)
			return ErrorResourceDoesNotExist{Identifier: tempStr, Err: errors.New(result.Result[0].Status.Message)}
		case FortiManagerNoPermission:
			// The session has expired. Clear the session so that we login and grab a new session next time.
			f.Client.session = ""
			return ErrorConnectionInvalidSession{Err: errors.New(result.Result[0].Status.Message)}
		case FortiManagerEmptyMemberInAddrGroup:
			tempStr := fmt.Sprintf("(Address Group :%s in ADOM:%s )", addrName, adom)
			return ErrorEmptyMemberInAddrGrp{Identifier: tempStr, Err: errors.New(result.Result[0].Status.Message)}
		case FortiManagerObjectInUse:
			tempStr := fmt.Sprintf("(ADOM:%s AddressName:%s) in FortiManager", adom, addrName)
			return ErrorClientDeleteData{Err: errors.New(result.Result[0].Status.Message), Identifier: tempStr}
		default:
			return errors.New(result.Result[0].Status.Message)
		}
	}
	return err
}

func (f *FortiManagerClient) Login() error {

	req := &requestLogin{
		ID:     f.Client.sessionId,
		Method: "exec",
		Params: []reqLoginParams{{
			URL: "/sys/login/user",
			DATA: reqLoginData{
				User:     f.Username,
				Password: f.Password,
			}},
		}}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		log.Error("Json Marshal Error : ", err)
		return ErrorClientMarshallingData{Err: err, Identifier: ""}
	}

	respBytes, err := f.Client.Post(reqBytes)
	if err != nil {
		log.Error("POST request failed from  FortiManager :", err)
		return ErrorUnknownConnectionIssue{Err: err}
	}

	var resp respLogin
	err = json.Unmarshal(respBytes, &resp)
	if err != nil {
		log.WithError(err).Error("Json Unmarshal Error for resp")
		return ErrorClientMarshallingData{Err: err, Identifier: "Un"}
	}

	if resp.Result[0].Status.Code != FortiManagerCodeOK {
		err := errors.New(resp.Result[0].Status.Message)
		log.WithError(err).Errorf("Failed to login to fortimanager. Response: %+v", resp)
		return err
	}

	f.Client.session = resp.Session
	return err
}

func (f *FortiManagerClient) Logout() {
	req1 := &requestLogin{ID: f.Client.sessionId,
		Method: "exec",
		Params: []reqLoginParams{{
			URL: "/sys/logout",
		}},
		Session: f.Client.session,
	}

	var res1 respLogin
	err := f.fortimanagerRestPost(req1, &res1, "", "")
	if err != nil {
		log.Debug("Failed to Logout from the FortiManager :", err)
	}
	f.Client.session = ""
}

func (f *FortiManagerClient) ListAllFirewallAddresses() ([]FortiFWAddress, error) {

	url := fmt.Sprintf("/pm/config/adom/%s/obj/firewall/address", f.Adom)
	req1 := &requestLogin{
		ID:     f.Client.sessionId,
		Method: "get",
		Params: []reqLoginParams{{
			URL: url,
		}},
	}

	var res1 respFWAddresses
	err := f.fortimanagerRestPost(req1, &res1, f.Adom, "")
	if err != nil {
		log.Error("Failed to get all FW addresses from the FortiManager :", err)
		return nil, err
	}

	fwAddresses := []FortiFWAddress{}
	for _, res := range res1.Result[0].Data {
		var fwAddress FortiFWAddress
		// Only IP based Address objects are handled by FortiManager
		if res.Type != FortiMgrIpMaskType {
			continue
		}
		fwAddress.Comment = res.Comment
		fwAddress.Name = res.Name
		fwAddress.IpAddr = res.Subnet[0]
		fwAddress.Mask = res.Subnet[1]
		fwAddresses = append(fwAddresses, fwAddress)
	}
	return fwAddresses, err

}

func (f *FortiManagerClient) GetFirewallAddress(fwAddress string) (FortiFWAddress, error) {

	var fwAddressObj FortiFWAddress

	url := fmt.Sprintf("/pm/config/adom/%s/obj/firewall/address/%s", f.Adom, fwAddress)
	req1 := &requestLogin{
		ID:     f.Client.sessionId,
		Method: "get",
		Params: []reqLoginParams{{
			URL: url,
		}},
	}

	var res1 respFWAddressByName
	err := f.fortimanagerRestPost(req1, &res1, f.Adom, fwAddress)
	if err != nil {
		log.Error("Failed to get the FW address from FortiManager :", err)
		return fwAddressObj, err
	}

	fwAddressObj.Comment = res1.Result[0].Data.Comment
	fwAddressObj.Name = res1.Result[0].Data.Name
	fwAddressObj.IpAddr = res1.Result[0].Data.Subnet[0]
	fwAddressObj.Mask = res1.Result[0].Data.Subnet[1]

	return fwAddressObj, err

}

// Create a Firewall Address object in FortiManager
// http POST request to FortiManager device
func (f *FortiManagerClient) CreateFirewallAddress(fortiFWAddr FortiFWAddress) error {

	url := fmt.Sprintf("/pm/config/adom/%s/obj/firewall/address/%s", f.Adom, fortiFWAddr.Name)

	req := &requestIpAddr{
		ID:     f.Client.sessionId,
		Method: "add",
		Params: []reqIpaddrParams{{
			DATA: ReqIpaddrData{
				Name:                fortiFWAddr.Name,
				Comment:             fortiFWAddr.Comment,
				Subnet:              []string{fortiFWAddr.IpAddr, fortiFWAddr.Mask},
				AssociatedInterface: []string{"any"},
			},
			URL: url,
		}},
	}

	var res respFWAddressByName
	err := f.fortimanagerRestPost(req, &res, f.Adom, fortiFWAddr.Name)
	if err != nil {
		log.Error("Failed to create the FW address in the FortiManager :", err)
		return err
	}

	return err
}

// Modify and/or Update the Firewall Address object
func (f *FortiManagerClient) UpdateFirewallAddress(fortiFWAddr FortiFWAddress) error {

	url := fmt.Sprintf("/pm/config/adom/%s/obj/firewall/address/%s", f.Adom, fortiFWAddr.Name)

	temp := []string{fortiFWAddr.AssociatedInterface}
	subnet := []string{fortiFWAddr.IpAddr, fortiFWAddr.Mask}
	req := &requestIpAddr{
		ID:     f.Client.sessionId,
		Method: "update",
		Params: []reqIpaddrParams{{
			DATA: ReqIpaddrData{
				Name:                fortiFWAddr.Name,
				Comment:             fortiFWAddr.Comment,
				Subnet:              subnet,
				AssociatedInterface: temp,
			},

			URL: url,
		}},
	}

	var res respFWAddressByName
	err := f.fortimanagerRestPost(req, &res, f.Adom, fortiFWAddr.Name)
	if err != nil {
		log.Error("Failed to update the FW address in FortiManager :", err)
		return err
	}

	return err
}

// Delete the Firewall Addresss Group in FortiManager, Arguments: Adom name, FW address name
func (f *FortiManagerClient) DeleteFirewallAddress(fortiFWAddr FortiFWAddress) error {

	url := fmt.Sprintf("/pm/config/adom/%s/obj/firewall/address/%s", f.Adom, fortiFWAddr.Name)

	req := &requestLogin{ID: f.Client.sessionId,
		Method: "delete",
		Params: []reqLoginParams{{
			URL: url,
		}},
	}

	var res respFWDeleteAddressByName
	err := f.fortimanagerRestPost(req, &res, f.Adom, fortiFWAddr.Name)
	if err != nil {
		log.Error("Failed to Delete the FW address in FortiManager :", err)
		return err
	}

	return err
}

// Get All Firewall Addresss Group in FortiManager, Arguments: Adom
func (f *FortiManagerClient) ListAllFirewallAddressGroups() ([]FortiFWAddressGroup, error) {

	//URL string for getting the FW address Group
	url := fmt.Sprintf("/pm/config/adom/%s/obj/firewall/addrgrp", f.Adom)
	req := &requestFWAddressGroup{
		ID:     f.Client.sessionId,
		Method: "get",
		Params: []reqFWAddressGroupParams{{
			URL: url,
		}},
	}

	var res respFWAddressGroups
	err := f.fortimanagerRestPost(req, &res, f.Adom, "")
	if err != nil {
		log.Error("Failed to get all the FW address Groups from FortiManager :", err)
		return nil, err
	}

	fwAddresses := []FortiFWAddressGroup{}
	for _, result := range res.Result[0].Data {
		var fwAddressGrp FortiFWAddressGroup
		fwAddressGrp.Comment = result.Comment
		fwAddressGrp.Name = result.Name
		fwAddressGrp.Members = result.Member
		fwAddresses = append(fwAddresses, fwAddressGrp)

	}
	return fwAddresses, err
}

// Get the Firewall Addresss Group in FortiManager, Arguments: Adom and firewall Address group name
func (f *FortiManagerClient) GetFirewallAddressGroup(fwAddressGroup string) (FortiFWAddressGroup, error) {

	var fwAddressGrpObj FortiFWAddressGroup

	//URL string for getting all FW address Group
	url := fmt.Sprintf("/pm/config/adom/%s/obj/firewall/addrgrp/%s", f.Adom, fwAddressGroup)

	req := &requestFWAddressGroup{
		ID:     f.Client.sessionId,
		Method: "get",
		Params: []reqFWAddressGroupParams{{
			URL: url,
		}},
	}

	var res respFWAddressGroupName
	err := f.fortimanagerRestPost(req, &res, f.Adom, fwAddressGroup)
	if err != nil {
		log.Error("Failed to get the FW address Group from FortiManager :", err)
		return fwAddressGrpObj, err
	}

	fwAddressGrpObj.Name = res.Result[0].Data.Name
	fwAddressGrpObj.Comment = res.Result[0].Data.Comment
	fwAddressGrpObj.Members = res.Result[0].Data.Member

	return fwAddressGrpObj, err
}

// Create a FW address Group, Arguments Firewall Address Group object and ADOM name
func (f *FortiManagerClient) UpdateFirewallAddressGroup(fwAddressGrp FortiFWAddressGroup) error {

	//create a URL string for FW address Group with ADOM name and Address Group Name
	url := fmt.Sprintf("/pm/config/adom/%s/obj/firewall/addrgrp/%s", f.Adom, fwAddressGrp.Name)
	req := &requestFWAddressGroup{
		ID:     f.Client.sessionId,
		Method: "update",
		Params: []reqFWAddressGroupParams{{
			URL: url,
			DATA: ReqFWAddressGroupData{
				Name:    fwAddressGrp.Name,
				Comment: fwAddressGrp.Comment,
				Member:  fwAddressGrp.Members,
			},
		}},
	}

	var res respFWAddressGroupName
	//http POST request to FortiManager
	err := f.fortimanagerRestPost(req, &res, f.Adom, fwAddressGrp.Name)
	if err != nil {
		log.Error("Failed to Update the FW address Group in FortiManager :", err)
		return err
	}

	return err
}

// Create a FW address Group, Arguments Firewall Address Group object and ADOM name
func (f *FortiManagerClient) CreateFirewallAddressGroup(fwAddrGrp FortiFWAddressGroup) error {

	//create a URL string for FW address Group with ADOM name and Address Group Name
	url := fmt.Sprintf("/pm/config/adom/%s/obj/firewall/addrgrp/%s", f.Adom, fwAddrGrp.Name)

	req := &requestFWAddressGroup{
		ID:     f.Client.sessionId,
		Method: "add",
		Params: []reqFWAddressGroupParams{{
			URL: url,
			DATA: ReqFWAddressGroupData{
				Name:    fwAddrGrp.Name,
				Comment: fwAddrGrp.Comment,
				Member:  fwAddrGrp.Members,
			},
		}},
	}

	var res respFWAddressGroupName
	//http POST request to FortiManager
	err := f.fortimanagerRestPost(req, &res, f.Adom, fwAddrGrp.Name)
	if err != nil {
		log.Error("Failed to create the FW address Group in FortiManager :", err)
	}

	return err
}

// Delete a FW address Group, Arguments Firewall Address Group Name and ADOM name
func (f *FortiManagerClient) DeleteFirewallAddressGroup(fwAddressGrpName string) error {

	//create a URL string for FW address Group with ADOM name and Address Group Name
	url := fmt.Sprintf("/pm/config/adom/%s/obj/firewall/addrgrp/%s", f.Adom, fwAddressGrpName)
	req := &requestFWAddressGroup{ID: f.Client.sessionId,
		Method: "delete",
		Params: []reqFWAddressGroupParams{{
			URL: url,
			DATA: ReqFWAddressGroupData{
				Name: fwAddressGrpName,
			},
		}},
	}
	var res respLogin
	//http POST request to FortiManager
	err := f.fortimanagerRestPost(req, &res, f.Adom, fwAddressGrpName)
	if err != nil {
		log.Error("Failed to delete the FW address Group in FortiManager :", err)
	}

	return err
}

// Get the policy package from FortiManager DB
func (f *FortiManagerClient) GetFirewallPolicyPackage(pkgName string) error {

	// build a URL string to get policy package from FM
	url := fmt.Sprintf("/pm/pkg/adom/%s/%s", f.Adom, pkgName)
	req := &reqFWPolicyPkg{ID: f.Client.sessionId,
		Method: "get",
		Params: []reqFWPolicyPkgParams{{
			URL: url,
		}},
	}

	var res respFWPolicyPkgName
	err := f.fortimanagerRestPost(req, &res, f.Adom, pkgName)
	if err != nil {
		log.WithError(err).Error("Failed to Get FW policy package in FortiManager")
	}

	return err
}

// Get the list of packages from FortiManager
func (f *FortiManagerClient) ListAllFirewallRulesInPkg(pkgName string) ([]FortiFWPolicy, error) {

	// build a URL string to get policy package from Fortimanager
	url := fmt.Sprintf("/pm/config/adom/%s/pkg/%s/firewall/policy", f.Adom, pkgName)
	req := &reqFWPolicyPkg{ID: f.Client.sessionId,
		Method: "get",
		Params: []reqFWPolicyPkgParams{{
			URL: url,
		}},
	}

	var res respFWPolicy
	err := f.fortimanagerRestPost(req, &res, f.Adom, pkgName)
	if err != nil {
		log.WithError(err).Error("Failed to Get FW policy in FortiManager")
		return nil, err
	}

	fwPolicies := []FortiFWPolicy{}
	for _, res1 := range res.Result[0].Data {
		var fwPolicy FortiFWPolicy
		fwPolicy.SrcAddr = make([]string, len(res1.SrcAddr))
		copy(fwPolicy.SrcAddr, res1.SrcAddr)
		fwPolicy.DstAddr = make([]string, len(res1.DstAddr))
		copy(fwPolicy.DstAddr, res1.DstAddr)
		fwPolicy.Service = make([]string, len(res1.Service))
		copy(fwPolicy.Service, res1.Service)
		fwPolicy.Action = res1.Action
		fwPolicy.Name = res1.Name
		fwPolicy.Comments = res1.Comments
		fwPolicies = append(fwPolicies, fwPolicy)
	}
	return fwPolicies, err
}
