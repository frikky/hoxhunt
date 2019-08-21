# Hoxhunt API
Fixed the API to be up to par with theirs actual API (partly, but still hacky)

## Supported functions
* List incidents
* Get incident details
* Change incident status
* List threats
* Get threat details

## Get your API key (it's not really an API key, but used for authentication)
* Open developer tools in your favorite browser
* Go to https://app.hoxhunt.com/incidents
* Look at any of the requests to https://app.hoxhunt.com/graphql
* Look for the "authorization" header. 
* Check the "organizationId" in one of the requests.
* Copy this into the next step :) 

## Install
```bash
go get github.com/frikky/hoxhunt
```

## Usage
```go
import github.com/frikky/hoxhunt

yourApiKey := "<YOUR API KEY>"
org := "<YOUR ORG ID KEY>"
hox := hoxhunt.CreateLogin(yourApiKey, org)

// Available functions
allIncidents, err := hox.ListIncidents()
allThreats, err := hox.ListThreats()
threatInfo, err := hox.GetThreat(threatId)
incidentInfo, err := hox.GetIncident(incidentId)

// No return value from request. Might be statusCode dependant? 
hox.CloseIncident(incidentId)
hox.ReopenIncident(incidentId)
```

## Implementation
I might release an implementation with TheHive alerts soon, as it's the reason I'm doing this work
