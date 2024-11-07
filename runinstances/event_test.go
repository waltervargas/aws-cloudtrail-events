package runinstances_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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
	if diff := cmp.Diff(want, event, cmpopts.IgnoreUnexported(runinstances.TagSpecificationSet{})); diff != "" {
		t.Errorf("Mismatch (-want +got):\n%s", diff)
	}
}

func TestRecordsListRunInstancesFromFile(t *testing.T) {
	file, err := os.Open("testdata/runinstances.json")
	if err != nil {
		t.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()
	var records runinstances.Records
	err = json.NewDecoder(file).Decode(&records)
	if err != nil {
		t.Fatalf("Failed to decode JSON: %v", err)
	}
}

func TestTagSpecificationSet_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name             string
		jsonData         []byte
		expectedIsHidden bool
		expectedTags     []runinstances.TagSpecificationItem
		expectError      bool
	}{
		{
			name: "Valid TagSpecificationSet with multiple tags",
			jsonData: []byte(`{
                "items": [
                    {
                        "resourceType": "instance",
                        "tags": [
                            {
                                "key": "environment",
                                "value": "production"
                            },
                            {
                                "key": "project",
                                "value": "my-project"
                            }
                        ]
                    }
                ]
            }`),
			expectedIsHidden: false,
			expectedTags: []runinstances.TagSpecificationItem{
				{
					ResourceType: "instance",
					Tags: []runinstances.Tag{
						{Key: "environment", Value: "production"},
						{Key: "project", Value: "my-project"},
					},
				},
			},
			expectError: false,
		},
		{
			name:             "Hidden TagSpecificationSet",
			jsonData:         []byte(`"HIDDEN_DUE_TO_SECURITY_REASONS"`),
			expectedIsHidden: true,
			expectedTags:     nil,
			expectError:      false,
		},
		{
			name:             "Unexpected Hidden Value",
			jsonData:         []byte(`"UNKNOWN_VALUE"`),
			expectedIsHidden: false,
			expectedTags:     nil,
			expectError:      true,
		},
		{
			name:             "Invalid JSON Type (number)",
			jsonData:         []byte(`12345`),
			expectedIsHidden: false,
			expectedTags:     nil,
			expectError:      true,
		},
		{
			name:             "Invalid JSON Format",
			jsonData:         []byte(`{"invalid": "json"`), // Missing closing brace
			expectedIsHidden: false,
			expectedTags:     nil,
			expectError:      true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var tagSpec runinstances.TagSpecificationSet
			err := json.Unmarshal(tc.jsonData, &tagSpec)

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("Unexpected error during unmarshalling: %v", err)
				return
			}
			if tagSpec.IsHidden() != tc.expectedIsHidden {
				t.Errorf("IsHidden mismatch: expected %v, got %v", tc.expectedIsHidden, tagSpec.IsHidden())
			}
			if (tagSpec.GetTags() == nil) != (tc.expectedTags == nil) {
				t.Errorf("Tags presence mismatch: expected %v, got %v", tc.expectedTags != nil, tagSpec.GetTags() != nil)
			} else if tagSpec.GetTags() != nil && tc.expectedTags != nil {
				if len(tagSpec.GetTags()) != len(tc.expectedTags) {
					t.Errorf("Expected %d TagSpecificationItems, got %d", len(tc.expectedTags), len(tagSpec.GetTags()))
				}
				for i, expectedItem := range tc.expectedTags {
					if i >= len(tagSpec.GetTags()) {
						break
					}
					actualItem := tagSpec.GetTags()[i]
					if actualItem.ResourceType != expectedItem.ResourceType {
						t.Errorf("ResourceType mismatch in item %d: expected %s, got %s", i, expectedItem.ResourceType, actualItem.ResourceType)
					}
					if len(actualItem.Tags) != len(expectedItem.Tags) {
						t.Errorf("Expected %d tags in item %d, got %d", len(expectedItem.Tags), i, len(actualItem.Tags))
					}
					for j, expectedTag := range expectedItem.Tags {
						if j >= len(actualItem.Tags) {
							break
						}
						actualTag := actualItem.Tags[j]
						if actualTag.Key != expectedTag.Key || actualTag.Value != expectedTag.Value {
							t.Errorf("Tag mismatch in item %d, tag %d: expected %+v, got %+v", i, j, expectedTag, actualTag)
						}
					}
				}
			}
		})
	}
}
