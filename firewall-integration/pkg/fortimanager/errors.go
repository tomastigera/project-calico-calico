package fortimanager

import "fmt"

// Error indicating a sessionTimeout, the session is invalid .
type ErrorConnectionInvalidSession struct {
	Err error
}

func (e ErrorConnectionInvalidSession) Error() string {
	return fmt.Sprintf("Invalid session: %v", e.Err)
}

// Error indicating an operation is not supported.
type ErrorResourceDoesNotExist struct {
	Err        error
	Identifier any
}

func (e ErrorResourceDoesNotExist) Error() string {
	return fmt.Sprintf("resource does not exist %v  with error: %v", e.Identifier, e.Err)
}

// Error indicating a resource already exists.  Used when attempting to create a
// resource that already exists.
type ErrorResourceAlreadyExists struct {
	Err        error
	Identifier any
}

func (e ErrorResourceAlreadyExists) Error() string {
	return fmt.Sprintf("resource %v already exists in FortiManager: %v", e.Identifier, e.Err)
}

// Error indicating Unauthorized connection to the FortiManager.
type ErrorConnectionUnauthorized struct {
	Err error
}

func (e ErrorConnectionUnauthorized) Error() string {
	return fmt.Sprintf("connection is unauthorized: %v", e.Err)
}

// Error indicating a problem with Marshall/UnMarshall in FM client
type ErrorClientMarshallingData struct {
	Err        error
	Identifier any
}

func (e ErrorClientMarshallingData) Error() string {
	return fmt.Sprintf("Error in Json %vMarshall: %v", e.Identifier, e.Err)
}

// Error indicating a problem with Marshall/UnMarshall in FM client
type ErrorClientDeleteData struct {
	Err        error
	Identifier any
}

func (e ErrorClientDeleteData) Error() string {
	return fmt.Sprintf("Resource %v used by FW policies, can't delete err:%v", e.Identifier, e.Err)
}

// Empty member address group created in FortiManager
type ErrorEmptyMemberInAddrGrp struct {
	Err        error
	Identifier any
}

func (e ErrorEmptyMemberInAddrGrp) Error() string {
	return fmt.Sprintf("%v have no member err:%v", e.Identifier, e.Err)
}

// Error indicating a problem connecting to the Fortidevice
type ErrorUnknownConnectionIssue struct {
	Err error
}

func (e ErrorUnknownConnectionIssue) Error() string {
	return fmt.Sprintf("connection is Invalid: %v", e.Err)
}
