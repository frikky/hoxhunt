# Hoxhunt API
As I struggle using other peoples' interfaces in general, I went about creating an API for them. It's purely based on how they work with GraphQL.

## Supported functions
* List incidents
* Get incident details
* Change incident status
* Get threats

## Get your API key (it's not really an API key, but used for authentication)
* Open developer tools in your favorite browser
* Go to https://app.hoxhunt.com/incidents
* Look at any of the requests to https://app.hoxhunt.com/graphql
* Look for the "authorization" header. 
* Copy this into the next step :) 

## Install
```bash
go get github.com/frikky/hoxhunt
```

## Usage
```go
import github.com/frikky/hoxhunt

yourApiKey := "<YOUR API KEY>"
hox := hoxhunt.CreateLogin(yourApiKey)

// Available functions
allIncidents, err := hox.ListIncidents()
threatInfo, err := login.GetThreat(threatId)
incidentInfo, err := login.GetIncident(incidentId)

// No return value it seems
login.CloseIncident(incidentId)
ReopenIncident(incidentId)
```

## Implementation
I might release an implementation with TheHive alerts soon, as it's the reason I'm doing this work
