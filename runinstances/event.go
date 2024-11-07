package runinstances

import (
	"encoding/json"
	"fmt"
)

// Records represent the CloudTrail records
type Records struct {
	Records []Event `json:"Records"`
}

// Event represents the CloudTrail event for eventName=runInstances
type Event struct {
	EventVersion       string            `json:"eventVersion"`
	UserIdentity       UserIdentity      `json:"userIdentity"`
	EventTime          string            `json:"eventTime"`
	EventSource        string            `json:"eventSource"`
	EventName          string            `json:"eventName"`
	AwsRegion          string            `json:"awsRegion"`
	SourceIPAddress    string            `json:"sourceIPAddress"`
	UserAgent          string            `json:"userAgent"`
	RequestParameters  RequestParameters `json:"requestParameters"`
	ResponseElements   ResponseElements  `json:"responseElements"`
	RequestID          string            `json:"requestID"`
	EventID            string            `json:"eventID"`
	ReadOnly           bool              `json:"readOnly"`
	EventType          string            `json:"eventType"`
	ManagementEvent    bool              `json:"managementEvent"`
	RecipientAccountID string            `json:"recipientAccountId"`
	EventCategory      string            `json:"eventCategory"`
	TLSDetails         TLSDetails        `json:"tlsDetails"`
	ErrorCode          string            `json:"errorCode,omitempty"`
	ErrorMessage       string            `json:"errorMessage,omitempty"`
}

// UserIdentity Struct
type UserIdentity struct {
	Type           string         `json:"type"`
	PrincipalID    string         `json:"principalId"`
	Arn            string         `json:"arn"`
	AccountID      string         `json:"accountId"`
	AccessKeyID    string         `json:"accessKeyId"`
	SessionContext SessionContext `json:"sessionContext"`
}

// SessionContext Struct
type SessionContext struct {
	SessionIssuer       SessionIssuer          `json:"sessionIssuer"`
	WebIDFederationData map[string]interface{} `json:"webIdFederationData"`
	Attributes          Attributes             `json:"attributes"`
}

// SessionIssuer Struct
type SessionIssuer struct {
	Type        string `json:"type"`
	PrincipalID string `json:"principalId"`
	Arn         string `json:"arn"`
	AccountID   string `json:"accountId"`
	UserName    string `json:"userName"`
}

// Attributes Struct
type Attributes struct {
	CreationDate     string `json:"creationDate"`
	MfaAuthenticated string `json:"mfaAuthenticated"`
}

// RequestParameters Struct
type RequestParameters struct {
	InstancesSet          InstancesSet                `json:"instancesSet"`
	UserData              string                      `json:"userData"`
	InstanceType          string                      `json:"instanceType"`
	BlockDeviceMapping    BlockDeviceMapping          `json:"blockDeviceMapping"`
	AvailabilityZone      string                      `json:"availabilityZone"`
	Tenancy               string                      `json:"tenancy"`
	Monitoring            Monitoring                  `json:"monitoring"`
	DisableAPITermination bool                        `json:"disableApiTermination"`
	DisableAPIStop        bool                        `json:"disableApiStop"`
	ClientToken           string                      `json:"clientToken"`
	NetworkInterfaceSet   NetworkInterfaceSet         `json:"networkInterfaceSet"`
	IamInstanceProfile    IamInstanceProfile          `json:"iamInstanceProfile"`
	TagSpecificationSet   TagSpecificationSetOrHidden `json:"tagSpecificationSet"`
	InstanceMarketOptions InstanceMarketOptions       `json:"instanceMarketOptions"`
}

// InstancesSet Struct
type InstancesSet struct {
	Items []InstanceItem `json:"items"`
}

// InstanceItem Struct
type InstanceItem struct {
	ImageID  string `json:"imageId"`
	MinCount int    `json:"minCount"`
	MaxCount int    `json:"maxCount"`
	KeyName  string `json:"keyName"`
}

// BlockDeviceMapping Struct
type BlockDeviceMapping struct {
	Items []BlockDeviceItem `json:"items"`
}

// BlockDeviceItem Struct
type BlockDeviceItem struct {
	DeviceName string `json:"deviceName"`
	Ebs        Ebs    `json:"ebs"`
}

// Ebs Struct
type Ebs struct {
	VolumeSize          int    `json:"volumeSize"`
	DeleteOnTermination bool   `json:"deleteOnTermination"`
	VolumeType          string `json:"volumeType"`
}

// Monitoring Struct
type Monitoring struct {
	Enabled bool `json:"enabled"`
}

// NetworkInterfaceSet Struct
type NetworkInterfaceSet struct {
	Items []NetworkInterfaceItem `json:"items"`
}

// NetworkInterfaceItem Struct
type NetworkInterfaceItem struct {
	DeviceIndex              int      `json:"deviceIndex"`
	SubnetID                 string   `json:"subnetId"`
	DeleteOnTermination      bool     `json:"deleteOnTermination"`
	AssociatePublicIPAddress bool     `json:"associatePublicIpAddress"`
	GroupSet                 GroupSet `json:"groupSet"`
}

// GroupSet Struct
type GroupSet struct {
	Items []GroupSetItem `json:"items"`
}

// GroupSetItem Struct
type GroupSetItem struct {
	GroupID string `json:"groupId"`
}

// IamInstanceProfile Struct
type IamInstanceProfile struct {
	Name string `json:"name"`
}

// TagSpecificationSetOrHidden represents either a set of tag specifications or
// a hidden marker indicating that the tag specifications are hidden for
// security reasons.
type TagSpecificationSetOrHidden struct {
	IsHidden bool
	Tags     *TagSpecificationSet
}

// UnmarshalJSON custom unmarshals TagSpecificationSetOrHidden from JSON,
// handling both hidden values and valid tag specifications.
func (t *TagSpecificationSetOrHidden) UnmarshalJSON(data []byte) error {
	var hidden string
	if err := json.Unmarshal(data, &hidden); err == nil {
		if hidden == "HIDDEN_DUE_TO_SECURITY_REASONS" {
			t.IsHidden = true
			t.Tags = nil
			return nil
		}
		return fmt.Errorf("unexpected hidden value: %s", hidden)
	}

	var tags TagSpecificationSet
	if err := json.Unmarshal(data, &tags); err == nil {
		t.IsHidden = false
		t.Tags = &tags
		return nil
	}

	return fmt.Errorf("tagSpecificationSet is neither hidden nor a valid TagSpecificationSet: %s", data)
}

// TagSpecificationSet Struct
type TagSpecificationSet struct {
	Items []TagSpecificationItem `json:"items"`
}

// TagSpecificationItem Struct
type TagSpecificationItem struct {
	ResourceType string `json:"resourceType"`
	Tags         []Tag  `json:"tags"`
}

// Tag Struct
type Tag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// InstanceMarketOptions Struct
type InstanceMarketOptions struct {
	MarketType  string      `json:"marketType"`
	SpotOptions SpotOptions `json:"spotOptions"`
}

// SpotOptions Struct
type SpotOptions struct {
	MaxPrice         string `json:"maxPrice"`
	SpotInstanceType string `json:"spotInstanceType"`
}

// ResponseElements Struct
type ResponseElements struct {
	RequestID     string       `json:"requestId"`
	ReservationID string       `json:"reservationId"`
	OwnerID       string       `json:"ownerId"`
	GroupSet      GroupSet     `json:"groupSet"`
	InstancesSet  InstancesSet `json:"instancesSet"`
}

// TLSDetails Struct
type TLSDetails struct {
	TlSVersion               string `json:"tlsVersion"`
	CipherSuite              string `json:"cipherSuite"`
	ClientProvidedHostHeader string `json:"clientProvidedHostHeader"`
}
