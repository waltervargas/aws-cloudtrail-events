package runinstances_test

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/waltervargas/aws-cloudtrail-events/runinstances"
)

func TestRunInstancesEventUnmarshal(t *testing.T) {
	jsonInput := `{
		"eventVersion": "1.05",
		"userIdentity": {
			"type": "IAMUser",
			"principalId": "AIDAEXAMPLE",
			"arn": "arn:aws:iam::123456789012:user/ExampleUser",
			"accountId": "123456789012",
			"accessKeyId": "ASIAEXAMPLE",
			"sessionContext": {
				"sessionIssuer": {
					"type": "Role",
					"principalId": "AROAXAMPLE",
					"arn": "arn:aws:iam::123456789012:role/ExampleRole",
					"accountId": "123456789012",
					"userName": "ExampleRole"
				},
				"attributes": {
					"creationDate": "2023-01-01T12:34:56Z",
					"mfaAuthenticated": "true"
				},
				"webIdFederationData": {}
			}
		},
		"eventTime": "2023-03-01T12:00:00Z",
		"eventSource": "ec2.amazonaws.com",
		"eventName": "RunInstances",
		"awsRegion": "us-east-1",
		"sourceIPAddress": "192.0.2.0",
		"userAgent": "aws-sdk-go",
		"requestID": "abcd1234",
		"eventID": "efgh5678",
		"requestParameters": {
			"instancesSet": {
				"items": [{
					"imageId": "ami-123456",
					"minCount": 1,
					"maxCount": 1,
					"keyName": "my-key-pair"
				}]
			},
			"instanceType": "t2.micro"
		},
		"responseElements": {
			"requestId": "request1234",
			"reservationId": "r-1234567890"
		},
		"readOnly": false,
		"eventType": "AwsApiCall",
		"managementEvent": true,
		"recipientAccountId": "123456789012",
		"eventCategory": "Management",
		"tlsDetails": {
			"tlsVersion": "TLSv1.2",
			"cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
			"clientProvidedHostHeader": "ec2.amazonaws.com"
		}
	}`

	var event runinstances.Event
	err := json.Unmarshal([]byte(jsonInput), &event)
	if err != nil {
		t.Fatalf("Error unmarshaling JSON: %v", err)
	}

	// Check if specific fields are correctly parsed
	if event.EventName != "RunInstances" {
		t.Errorf("Expected event name to be 'RunInstances', got %s", event.EventName)
	}

	if event.AwsRegion != "us-east-1" {
		t.Errorf("Expected aws region to be 'us-east-1', got %s", event.AwsRegion)
	}

	if event.UserIdentity.Type != "IAMUser" {
		t.Errorf("Expected user identity type to be 'IAMUser', got %s", event.UserIdentity.Type)
	}

	if event.RequestParameters.InstanceType != "t2.micro" {
		t.Errorf("Expected instance type to be 't2.micro', got %s", event.RequestParameters.InstanceType)
	}

	if len(event.RequestParameters.InstancesSet.Items) == 0 || event.RequestParameters.InstancesSet.Items[0].ImageID != "ami-123456" {
		t.Errorf("Expected image ID to be 'ami-123456', got %v", event.RequestParameters.InstancesSet.Items[0].ImageID)
	}
}

func TestRunInstancesEvent(t *testing.T) {
	data := `{
		"eventVersion": "1.08",
		"userIdentity": {
			"type": "IAMUser",
			"principalId": "ABCDEFGHIJKLMN",
			"arn": "arn:aws:iam::123456789012:user/example",
			"accountId": "123456789012",
			"accessKeyId": "ABCDEFEXAMPLEKEY",
			"sessionContext": {
				"sessionIssuer": {
					"type": "Role",
					"principalId": "ABCDEFGHIJKLMN",
					"arn": "arn:aws:iam::123456789012:role/example-role",
					"accountId": "123456789012",
					"userName": "example-role"
				},
				"webIdFederationData": {},
				"attributes": {
					"creationDate": "2023-01-01T12:00:00Z",
					"mfaAuthenticated": "true"
				}
			}
		},
		"eventTime": "2023-01-01T12:00:00Z",
		"eventSource": "ec2.amazonaws.com",
		"eventName": "RunInstances",
		"awsRegion": "us-west-2",
		"sourceIPAddress": "192.0.2.0",
		"userAgent": "console.amazonaws.com",
		"requestParameters": {
			"instancesSet": {
				"items": [{
					"imageId": "ami-123456",
					"minCount": 1,
					"maxCount": 1,
					"keyName": "example-key"
				}]
			},
			"userData": "example-user-data",
			"instanceType": "t2.micro",
			"availabilityZone": "us-west-2a",
			"tenancy": "default",
			"monitoring": {
				"enabled": true
			},
			"disableApiTermination": false,
			"disableApiStop": false,
			"clientToken": "token12345",
			"networkInterfaceSet": {
				"items": [{
					"deviceIndex": 0,
					"subnetId": "subnet-12345",
					"deleteOnTermination": true,
					"associatePublicIpAddress": true,
					"groupSet": {
						"items": [{
							"groupId": "sg-12345"
						}]
					}
				}]
			},
			"iamInstanceProfile": {
				"name": "example-profile"
			}
		},
		"responseElements": {
			"requestId": "request-12345",
			"reservationId": "r-12345",
			"ownerId": "123456789012"
		},
		"eventID": "e72fd221-3cbf-4410-9eda-586f4d732f88",
		"readOnly": false,
		"eventType": "AwsApiCall",
		"managementEvent": true,
		"recipientAccountId": "123456789012",
		"eventCategory": "Management",
		"tlsDetails": {
			"tlsVersion": "TLSv1.2",
			"cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
			"clientProvidedHostHeader": "ec2.amazonaws.com"
		}
	}`

	// Decode the JSON data into a RunInstancesEvent
	var event runinstances.Event
	err := json.Unmarshal([]byte(data), &event)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// Define the expected (want) structure
	want := runinstances.Event{
		EventVersion: "1.08",
		UserIdentity: runinstances.UserIdentity{
			Type:        "IAMUser",
			PrincipalID: "ABCDEFGHIJKLMN",
			Arn:         "arn:aws:iam::123456789012:user/example",
			AccountID:   "123456789012",
			AccessKeyID: "ABCDEFEXAMPLEKEY",
			SessionContext: runinstances.SessionContext{
				SessionIssuer: runinstances.SessionIssuer{
					Type:        "Role",
					PrincipalID: "ABCDEFGHIJKLMN",
					Arn:         "arn:aws:iam::123456789012:role/example-role",
					AccountID:   "123456789012",
					UserName:    "example-role",
				},
				Attributes: runinstances.Attributes{
					CreationDate:     "2023-01-01T12:00:00Z",
					MfaAuthenticated: "true",
				},
				WebIDFederationData: map[string]interface{}{},
			},
		},
		EventTime:       "2023-01-01T12:00:00Z",
		EventSource:     "ec2.amazonaws.com",
		EventName:       "RunInstances",
		AwsRegion:       "us-west-2",
		SourceIPAddress: "192.0.2.0",
		UserAgent:       "console.amazonaws.com",
		RequestParameters: runinstances.RequestParameters{
			InstancesSet: runinstances.InstancesSet{
				Items: []runinstances.InstanceItem{
					{
						ImageID:  "ami-123456",
						MinCount: 1,
						MaxCount: 1,
						KeyName:  "example-key",
					},
				},
			},
			UserData:         "example-user-data",
			InstanceType:     "t2.micro",
			AvailabilityZone: "us-west-2a",
			Tenancy:          "default",
			Monitoring: runinstances.Monitoring{
				Enabled: true,
			},
			DisableAPITermination: false,
			DisableAPIStop:        false,
			ClientToken:           "token12345",
			NetworkInterfaceSet: runinstances.NetworkInterfaceSet{
				Items: []runinstances.NetworkInterfaceItem{
					{
						DeviceIndex:              0,
						SubnetID:                 "subnet-12345",
						DeleteOnTermination:      true,
						AssociatePublicIPAddress: true,
						GroupSet: runinstances.GroupSet{
							Items: []runinstances.GroupSetItem{
								{GroupID: "sg-12345"},
							},
						},
					},
				},
			},
			IamInstanceProfile: runinstances.IamInstanceProfile{
				Name: "example-profile",
			},
		},
		ResponseElements: runinstances.ResponseElements{
			RequestID:     "request-12345",
			ReservationID: "r-12345",
			OwnerID:       "123456789012",
		},
		EventID:            "e72fd221-3cbf-4410-9eda-586f4d732f88",
		ReadOnly:           false,
		EventType:          "AwsApiCall",
		ManagementEvent:    true,
		RecipientAccountID: "123456789012",
		EventCategory:      "Management",
		TLSDetails: runinstances.TLSDetails{
			TlSVersion:               "TLSv1.2",
			CipherSuite:              "ECDHE-RSA-AES128-GCM-SHA256",
			ClientProvidedHostHeader: "ec2.amazonaws.com",
		},
	}

	// Compare the event and want using cmp.Diff
	if diff := cmp.Diff(want, event); diff != "" {
		t.Errorf("Mismatch (-want +got):\n%s", diff)
	}
}
