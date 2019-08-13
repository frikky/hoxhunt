# UPDATE: Deprecated - Don't use this
* As they changed their graphql calls which made this bug out, and they made an actual REST API available, this is now deprecated, and not working anymore

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
threatInfo, err := hox.GetThreat(threatId)
incidentInfo, err := hox.GetIncident(incidentId)

// No return value from request. Might be statusCode dependant? 
hox.CloseIncident(incidentId)
hox.ReopenIncident(incidentId)
```

## Implementation
I might release an implementation with TheHive alerts soon, as it's the reason I'm doing this work
