[![Go Reference](https://pkg.go.dev/badge/github.com/waltervargas/aws-cloudtrail-events.svg)](https://pkg.go.dev/github.com/waltervargas/aws-cloudtrail-events)[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)[![Go Report Card](https://goreportcard.com/badge/github.com/waltervargas/aws-cloudtrail-events)](https://goreportcard.com/report/github.com/waltervargas/aws-cloudtrail-events)

# AWS CloudTrail Events for Go
aws-cloudtrail-events is a Go module that provides a structured and easy-to-use interface for working with AWS CloudTrail events, starting with the RunInstances event. This module is designed for platform engineers, AWS developers, and architects who need to parse, manage, and process CloudTrail events efficiently.

## Features

- Structs for AWS CloudTrail `RunInstances` event with full coverage of request and response parameters.
- Easy marshaling and unmarshaling of CloudTrail event data in JSON format.
- Designed for integration into platform engineering and AWS-based workflows.
- Extensible to support additional CloudTrail event types in the future.

## Installation

To install the module, run:

```bash
go get github.com/waltervargas/aws-cloudtrail-events
```

## Usage

### Parse `RunInstances` Event

```go
import (
    "github.com/waltervargas/aws-cloudtrail-events"
    "encoding/json"
    "log"
)

func main() {
    var event awscloudtrailevents.RunInstancesEvent
    data := `{"eventVersion":"1.08","userIdentity":{...}}` // Example JSON data

    err := json.Unmarshal([]byte(data), &event)
    if err != nil {
        log.Fatalf("Error parsing event: %v", err)
    }

    log.Printf("Parsed Event: %+v", event)
}
```

### Marshalling Event Data
To marshal the `RunInstances` event back into JSON:

```go
jsonData, err := json.Marshal(event)
if err != nil {
    log.Fatalf("Error marshalling event: %v", err)
}
log.Printf("JSON Data: %s", jsonData)
```

### Supported Events
Currently, the module supports the following event:

 - RunInstances (for EC2 instance creation events)

### TODO

While aws-cloudtrail-events provides support for the RunInstances event, several features and improvements are planned:

- Support for more CloudTrail events.
- Enhanced error handling and validation.
- Support for filtering and querying events.
- Examples and documentation for integrating with different AWS services and platforms.

Contributions are welcome to help implement these features and improve this package.
