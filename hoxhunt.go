package hoxhunt

import (
	"encoding/json"
	"fmt"
	"github.com/levigross/grequests"
	"time"
)

type IncidentListData struct {
	Incidents []struct {
		Typename    string    `json:"__typename"`
		ID          string    `json:"_id"`
		CreatedAt   time.Time `json:"createdAt"`
		PolicyName  string    `json:"policyName"`
		State       string    `json:"state"`
		ThreatCount int       `json:"threatCount"`
	} `json:"incidents"`
}

type IncidentListWrapper struct {
	Data IncidentListData `json:"data"`
	Raw  []byte           `json:"-"`
}

type HoxhuntData struct {
	Url    string
	Apikey string
	Ro     grequests.RequestOptions
}

type IncidentWrapper struct {
	Data IncidentData `json:"data"`
	Raw  []byte       `json:"-"`
}

type ThreatWrapper struct {
	Data ThreatData `json:"data"`
	Raw  []byte     `json:"-"`
}

type ThreatData struct {
	CurrentUser struct {
		Typename     string `json:"__typename"`
		ID           string `json:"_id"`
		IsSuperAdmin bool   `json:"isSuperAdmin"`
	} `json:"currentUser"`
	Threats []struct {
		Typename  string    `json:"__typename"`
		ID        string    `json:"_id"`
		CreatedAt time.Time `json:"createdAt"`
		Email     struct {
			Typename    string `json:"__typename"`
			Attachments []struct {
				TypeName  string  `json:"__typename"`
				Hash      string  `json:"hash"`
				Name      string  `json:"name"`
				PublicUrl string  `json:"publicUrl"`
				Score     float64 `json:"score"`
				Type      string  `json:"type"`
			} `json:"attachments"`
			From []struct {
				Typename string `json:"__typename"`
				Address  string `json:"address"`
				Name     string `json:"name"`
			} `json:"from"`
			Headers []struct {
				Typename string   `json:"__typename"`
				Name     string   `json:"name"`
				Value    []string `json:"value"`
			} `json:"headers"`
			Mime struct {
				Typename  string `json:"__typename"`
				PublicURL string `json:"publicUrl"`
			} `json:"mime"`
			SanitizedHTML string      `json:"sanitizedHtml"`
			SanitizedText interface{} `json:"sanitizedText"`
			Subject       string      `json:"subject"`
			To            []struct {
				Typename string `json:"__typename"`
				Address  string `json:"address"`
				Name     string `json:"name"`
			} `json:"to"`
		} `json:"email"`
		Enrichments struct {
			Typename string `json:"__typename"`
			Hops     []struct {
				Typename  string  `json:"__typename"`
				By        string  `json:"by"`
				ByScore   float64 `json:"byScore"`
				From      string  `json:"from"`
				FromScore float64 `json:"fromScore"`
			} `json:"hops"`
			Links []struct {
				Typename string  `json:"__typename"`
				Href     string  `json:"href"`
				Label    string  `json:"label"`
				Score    float64 `json:"score"`
			} `json:"links"`
		} `json:"enrichments"`
		EscalationEmail interface{} `json:"escalationEmail"`
		FeedbackSentAt  interface{} `json:"feedbackSentAt"`
		Organization    struct {
			Typename      string      `json:"__typename"`
			ID            string      `json:"_id"`
			Name          string      `json:"name"`
			Notifications interface{} `json:"notifications"`
		} `json:"organization"`
		ReporterUser struct {
			Typename string `json:"__typename"`
			ID       string `json:"_id"`
			Emails   []struct {
				Typename string `json:"__typename"`
				Address  string `json:"address"`
			} `json:"emails"`
			Player struct {
				Typename string `json:"__typename"`
				Stats    struct {
					Typename    string  `json:"__typename"`
					FailureRate float64 `json:"failureRate"`
					Success     int     `json:"success"`
				} `json:"stats"`
			} `json:"player"`
			Profile struct {
				Typename  string `json:"__typename"`
				FirstName string `json:"firstName"`
				LastName  string `json:"lastName"`
			} `json:"profile"`
		} `json:"reporterUser"`
		Severity      string `json:"severity"`
		UserModifiers struct {
			Typename          string      `json:"__typename"`
			UserActedOnThreat interface{} `json:"userActedOnThreat"`
		} `json:"userModifiers"`
	} `json:"threats"`
}

type IncidentData struct {
	Incidents []struct {
		Typename   string    `json:"__typename"`
		ID         string    `json:"_id"`
		CreatedAt  time.Time `json:"createdAt"`
		PolicyName string    `json:"policyName"`
		State      string    `json:"state"`
		Threats    []struct {
			Typename  string    `json:"__typename"`
			ID        string    `json:"_id"`
			CreatedAt time.Time `json:"createdAt"`
			Email     struct {
				Typename string `json:"__typename"`
				From     []struct {
					Typename string `json:"__typename"`
					Address  string `json:"address"`
				} `json:"from"`
				Subject string `json:"subject"`
			} `json:"email"`
			ReporterUser struct {
				Typename string `json:"__typename"`
				ID       string `json:"_id"`
				Emails   []struct {
					Typename string `json:"__typename"`
					Address  string `json:"address"`
				} `json:"emails"`
			} `json:"reporterUser"`
		} `json:"threats"`
	} `json:"incidents"`
}

// Isn't incidentId per customer? What
// Doesn't get an error with: incidentId = "asd"
func (hoxhunt *HoxhuntData) ReopenIncident(incidentId string) error {
	data := fmt.Sprintf(`{"operationName":"UpdateIncidentState","variables":{"incidentId":"%s","state":"OPEN"},"query":"mutation UpdateIncidentState($incidentId: ID!, $state: IncidentState!) {\n  updateIncidentState(incidentId: $incidentId, state: $state) {\n    _id\n    state\n    __typename\n  }\n}\n"}`, incidentId)

	hoxhunt.Ro.JSON = data

	_, err := grequests.Post(hoxhunt.Url, &hoxhunt.Ro)
	return err
}

func (hoxhunt *HoxhuntData) CloseIncident(incidentId string) error {
	data := fmt.Sprintf(`{"operationName":"UpdateIncidentState","variables":{"incidentId":"%s","state":"RESOLVED"},"query":"mutation UpdateIncidentState($incidentId: ID!, $state: IncidentState!) {\n  updateIncidentState(incidentId: $incidentId, state: $state) {\n    _id\n    state\n    __typename\n  }\n}\n"}`, incidentId)

	hoxhunt.Ro.JSON = data

	_, err := grequests.Post(hoxhunt.Url, &hoxhunt.Ro)
	return err
}

func (hoxhunt *HoxhuntData) ListIncidents() (*IncidentListWrapper, error) {
	data := `{"operationName":"IncidentListQuery","variables":{"incidentState":"OPEN","sort":"createdAt_DESC"},"query":"query IncidentListQuery($policyName: IncidentPolicy, $organizationId: ID, $incidentState: IncidentState, $sort: [Incident_sort]) {\n  incidents(filter: {organizationId_eq: $organizationId, policyName_eq: $policyName, state_eq: $incidentState}, sort: $sort) {\n    _id\n    createdAt\n    policyName\n    state\n    threatCount\n    __typename\n  }\n}\n"}`

	hoxhunt.Ro.JSON = data

	ret, err := grequests.Post(hoxhunt.Url, &hoxhunt.Ro)
	fmt.Println(ret)

	parsedRet := new(IncidentListWrapper)
	err = json.Unmarshal(ret.Bytes(), parsedRet)
	if err != nil {
		return parsedRet, err
	}

	parsedRet.Raw = ret.Bytes()

	return parsedRet, nil
}

func (hoxhunt *HoxhuntData) GetIncident(incidentId string) (*IncidentWrapper, error) {
	data := fmt.Sprintf(`{"operationName":"IncidentDetailsContainerQuery","variables":{"incidentId":"%s"},"query":"query IncidentDetailsContainerQuery($incidentId: ID!) {\n  incidents(filter: {_id_eq: $incidentId}) {\n    _id\n    createdAt\n    policyName\n    state\n    threats(sort: createdAt_DESC, first: 100) {\n      _id\n      createdAt\n      email {\n        subject\n        from {\n          address\n          __typename\n        }\n        __typename\n      }\n      reporterUser {\n        _id\n        emails {\n          address\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n"}`, incidentId)

	hoxhunt.Ro.JSON = data

	ret, err := grequests.Post(hoxhunt.Url, &hoxhunt.Ro)

	parsedRet := new(IncidentWrapper)
	err = json.Unmarshal(ret.Bytes(), parsedRet)
	if err != nil {
		return parsedRet, err
	}

	parsedRet.Raw = ret.Bytes()
	return parsedRet, nil
}

func (hoxhunt *HoxhuntData) GetThreat(threatId string) (*ThreatWrapper, error) {
	data := fmt.Sprintf(`{"operationName":"RateThreatContainerQuery","variables":{"id":"%s"},"query":"query RateThreatContainerQuery($id: ID!) {\n  currentUser {\n    _id\n    isSuperAdmin\n    __typename\n  }\n  threats(filter: {_id_eq: $id}) {\n    _id\n    severity\n    createdAt\n    feedbackSentAt\n    userModifiers {\n      userActedOnThreat\n      __typename\n    }\n    enrichments {\n      hops {\n        from\n        fromScore\n        by\n        byScore\n        __typename\n      }\n      links {\n        label\n        href\n        score\n        __typename\n      }\n      __typename\n    }\n    email {\n      subject\n      sanitizedHtml\n      sanitizedText\n      headers {\n        name\n        value\n        __typename\n      }\n      from {\n        name\n        address\n        __typename\n      }\n      to {\n        name\n        address\n        __typename\n      }\n      attachments {\n        type\n        hash\n        size\n        name\n        publicUrl\n        score\n        __typename\n      }\n      mime {\n        publicUrl\n        __typename\n      }\n      __typename\n    }\n    organization {\n      _id\n      name\n      notifications {\n        threatEscalationEmails\n        __typename\n      }\n      __typename\n    }\n    escalationEmail {\n      sendDate\n      __typename\n    }\n    escalationEmail {\n      sendDate\n      message\n      __typename\n    }\n    reporterUser {\n      ...PlayerCardUserFragment\n      __typename\n    }\n    __typename\n  }\n}\n\nfragment PlayerCardUserFragment on User {\n  _id\n  profile {\n    firstName\n    lastName\n    __typename\n  }\n  emails {\n    address\n    __typename\n  }\n  player {\n    stats {\n      success\n      failureRate\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n"}`, threatId)

	hoxhunt.Ro.JSON = data

	ret, err := grequests.Post(hoxhunt.Url, &hoxhunt.Ro)

	parsedRet := new(ThreatWrapper)
	err = json.Unmarshal(ret.Bytes(), parsedRet)
	if err != nil {
		return parsedRet, err
	}

	parsedRet.Raw = ret.Bytes()
	return parsedRet, nil
}

func CreateLogin(apikey string) HoxhuntData {
	return HoxhuntData{
		Url:    "https://app.hoxhunt.com/graphql",
		Apikey: apikey,
		Ro: grequests.RequestOptions{
			Headers: map[string]string{
				"authorization": apikey,
				"Content-Type":  "application/json",
			},
			RequestTimeout:     time.Duration(30) * time.Second,
			InsecureSkipVerify: true,
		},
	}
}
