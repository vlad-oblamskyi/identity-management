package main

import (
	"errors"
	"fmt"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

type IdentityManagement struct {
}

type DataEntry struct {
	Key                   string     `json:"key"`
        Value                 string     `json:"value"`
        Approved              bool       `json:"approved"`
	ApprovingInstitution  string     `json:"approvingInstitution"`
	VisibilityList        []string   `json:"visibilityList"`
	VisibilityRequests    []string   `json:"visibilityRequests"`
}

type Person struct {
	Id        string       `json:"id"`
	Password  string       `json:"password"`
	Data      []DataEntry  `json:"data"`
}

type PendingApproval struct {
	Id        string     `json:"id"`
	Data      DataEntry  `json:"data"`
}

type SecureDataEntry struct {
	Key         string    `json:"key"`
	Value       string    `json:"value"`
	Approved    bool      `json:"approved"`
	RequestSent bool      `json:"requestSent"`
}

type SecurePerson struct {
	Id        string             `json:"id"`
	Data      []SecureDataEntry  `json:"data"`
}

func (t *IdentityManagement) Init(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	return nil, nil
}

func (t *IdentityManagement) Invoke(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	switch function {
	case "addPerson":
		if len(args) != 3 { 
			return nil, errors.New("Incorrect number of arguments. Id, Password and Data entries are expected!");
		}
		id := args[0]
		password := getHash(args[1])
		var data []DataEntry
		if err := json.Unmarshal([]byte(args[2]), &data); err != nil {
			panic(err)
		}

		person := &Person {
			Id: id,
			Password: password,
			Data: data,
		}
		jsonPerson, err := json.Marshal(person)
		if err != nil { 
			panic(err)
		}
		stub.PutState(id, jsonPerson) 

		return nil, nil
	case "updateData":
		if len(args) != 3 { 
			return nil, errors.New("Incorrect number of arguments. Id, Password and Data entries are expected!");
		}
		id := args[0]
		password := getHash(args[1])
		var newData []DataEntry
		if err := json.Unmarshal([]byte(args[2]), &newData); err != nil {
			panic(err)
		}
		// get existing person
		jsonPerson, err := stub.GetState(id)
		if err != nil {
			return nil, errors.New("Error retrieving person's state!");
		}
		var person Person
		if err := json.Unmarshal(jsonPerson, &person); err != nil {
			panic(err)
		}
		// check password
		if person.Password != password {
			return nil, errors.New("Incorrect password provided!");
		}
		// update person's data
		for i := 0; i < len(person.Data); i ++ {
			for j := 0; j < len(newData); j++ {
				if newData[i].Key == person.Data[i].Key {
					person.Data[i].Approved = false
					person.Data[i].Value = newData[i].Value;
				}
			}
		}
		// add new data fields
		for i := 0; i < len(newData); i++ {
			if !containsData(person.Data, newData[i]) {
				person.Data = append(person.Data, newData[i]);
			}
		}
		// marshal and update state
		updatedJsonPerson, err := json.Marshal(person)
		if err != nil { 
			panic(err)
		}
		stub.PutState(id, updatedJsonPerson) 

		return nil, nil
	case "approve":
		if len(args) != 2 {
			return nil, errors.New("Incorrect number of arguments. Id and Data key are expected!");
		}
		id := args[0]
		dataKey := args[1]
		jsonPerson, err := stub.GetState(id)
		if err != nil {
			return nil, errors.New("Error retrieving person's state!");
		}
		var person Person
		if err := json.Unmarshal(jsonPerson, &person); err != nil {
			panic(err)
		}
		for i := 0; i < len(person.Data); i ++ {
			if dataKey == person.Data[i].Key {
				person.Data[i].Approved = true
			}
		}
		updatedJsonPerson, err := json.Marshal(person)
		if err != nil {
			panic(err)
		}
		stub.PutState(id, updatedJsonPerson)

		return nil, nil
	case "requestPermissionForData":
		if len(args) != 3 {
			return nil, errors.New("Incorrect number of arguments. Requestor Id, Data owner Id and Data key are expected!");
		}
		requestorId := args[0]
		dataOwnerId := args[1]
		dataKey := args[2]

		jsonPerson, err := stub.GetState(dataOwnerId)
		if err != nil {
			return nil, errors.New("Error retrieving person's state!");
		}
		var person Person
		if err := json.Unmarshal(jsonPerson, &person); err != nil {
			panic(err)
		}
		for i := 0; i < len(person.Data); i++ {
			if dataKey == person.Data[i].Key {
				person.Data[i].VisibilityRequests = append(person.Data[i].VisibilityRequests, requestorId)
			}
		}
		updatedJsonPerson, err := json.Marshal(person)
		if err != nil {
			panic(err)
		}
		stub.PutState(dataOwnerId, updatedJsonPerson)

		return nil, nil
	case "grantPermissionForData":
		if len(args) != 3 {
			return nil, errors.New("Incorrect number of arguments. Data owner Id, Requestor Id and Data key are expected!");
		}
		dataOwnerId := args[0]
		requestorId := args[1]
		dataKey := args[2]

		jsonPerson, err := stub.GetState(dataOwnerId)
		if err != nil {
			return nil, errors.New("Error retrieving person's state!");
		}
		var person Person
		if err := json.Unmarshal(jsonPerson, &person); err != nil {
			panic(err)
		}
		for i := 0; i < len(person.Data); i++ {
			if dataKey == person.Data[i].Key {
				person.Data[i].VisibilityList = append(person.Data[i].VisibilityList, requestorId)
				newVisibilityRequests := person.Data[i].VisibilityRequests[:0]
				for _, x := range person.Data[i].VisibilityRequests {
					if x != requestorId {
						newVisibilityRequests = append(newVisibilityRequests, x)
					}
				}
				person.Data[i].VisibilityRequests = newVisibilityRequests
			}
		}
		updatedJsonPerson, err := json.Marshal(person)
		if err != nil {
			panic(err)
		}
		stub.PutState(dataOwnerId, updatedJsonPerson)

		return nil, nil
	case "revokePermissionForData":
		if len(args) != 3 {
			return nil, errors.New("Incorrect number of arguments. Data owner Id, Requestor Id and Data key are expected!");
		}
		dataOwnerId := args[0]
		requestorId := args[1]
		dataKey := args[2]

		jsonPerson, err := stub.GetState(dataOwnerId)
		if err != nil {
			return nil, errors.New("Error retrieving person's state!");
		}
		var person Person
		if err := json.Unmarshal(jsonPerson, &person); err != nil {
			panic(err)
		}
		for i := 0; i < len(person.Data); i++ {
			if dataKey == person.Data[i].Key {
				person.Data[i].VisibilityRequests = append(person.Data[i].VisibilityRequests, requestorId)
				newVisibilityList := person.Data[i].VisibilityList[:0]
				for _, x := range person.Data[i].VisibilityList {
					if x != requestorId {
						newVisibilityList = append(newVisibilityList, x)
					}
				}
				person.Data[i].VisibilityList = newVisibilityList
			}
		}
		updatedJsonPerson, err := json.Marshal(person)
		if err != nil {
			panic(err)
		}
		stub.PutState(dataOwnerId, updatedJsonPerson)

		return nil, nil
	default:
		return nil, errors.New("Unsupported operation")
	}
}

func (t *IdentityManagement) Query(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	switch function {
	case "getPendingApprovalList":
		if len(args) != 1 {
			return nil, errors.New("Incorrect number of arguments. Institution is expected!");
		}
		institution := args[0]

		keysIter, err := stub.RangeQueryState("0", "zzzzzzzzzzzzzzzzzz")
		if err != nil {
			return nil, errors.New("Error accessing state!")
		}
		defer keysIter.Close()

		var pendingApprovals []PendingApproval
		for keysIter.HasNext() {
			key, _, iterErr := keysIter.Next()
			if iterErr != nil {
				return nil, errors.New("Error accessing state!")
			}
			jsonPerson, err := stub.GetState(key)
			if err != nil {
				return nil, errors.New("Error retrieving person's state!");
			}
			var person Person
			if err := json.Unmarshal(jsonPerson, &person); err != nil {
				panic(err)
			}
			for i := 0; i < len(person.Data); i ++ {
				if person.Data[i].ApprovingInstitution == string(institution) && !person.Data[i].Approved {
					pendingApproval := PendingApproval {
						Id: person.Id,
						Data: person.Data[i],
					}
					pendingApprovals = append(pendingApprovals, pendingApproval)
				}
			}
		}
		return json.Marshal(pendingApprovals)
	case "getPerson":
		if len(args) != 2 {
			return nil, errors.New("Incorrect number of arguments. Id and password are expected!");
		}
		id := args[0]
		password := getHash(args[1])
		jsonPerson, err := stub.GetState(id)
		if err != nil {
			return nil, errors.New("Error retrieving person's state!");
		}
		if jsonPerson == nil {
			return nil, nil
		}
		var person Person
		if err := json.Unmarshal(jsonPerson, &person); err != nil {
			panic(err)
		}
		if person.Password != password {
			return nil, errors.New("Incorrect password provided!");
		}
		return jsonPerson, nil
	case "getPersonForRequestor":
		if len(args) != 3 {
			return nil, errors.New("Incorrect number of arguments. Requestor Id, password and Owner ID are expected!");
		}
		requestorId := args[0]
		password := getHash(args[1])
		ownerId := args[2]

		// check requestor's password
		jsonRequestorPerson, err := stub.GetState(requestorId)
		if err != nil {
			return nil, errors.New("Error retrieving person's state!");
		}
		var requestorPerson Person
		if err := json.Unmarshal(jsonRequestorPerson, &requestorPerson); err != nil {
			panic(err)
		}
		if requestorPerson.Password != password {
			return nil, errors.New("Incorrect password provided!");
		}

		// create secure person view for requestor
		jsonPerson, err := stub.GetState(ownerId)
		if err != nil {
			return nil, errors.New("Error retrieving person's state!");
		}
		if jsonPerson == nil {
			return nil, nil
		}
		var person Person
		if err := json.Unmarshal(jsonPerson, &person); err != nil {
			panic(err)
		}
		var secureDataEntries []SecureDataEntry
		for i := 0; i < len(person.Data); i ++ {
			var dataValue string
			var requestSent bool
			if (contains(person.Data[i].VisibilityList, requestorId)) {
				dataValue = person.Data[i].Value
			}
			if (contains(person.Data[i].VisibilityRequests, requestorId)) {
				requestSent = true
			}
			secureDataEntry := SecureDataEntry {
				Key: person.Data[i].Key,
				Value: dataValue,
				Approved: person.Data[i].Approved,
				RequestSent: requestSent,
			}
			secureDataEntries = append(secureDataEntries, secureDataEntry)
		}
		securePerson := &SecurePerson {
			Id: person.Id,
			Data: secureDataEntries,
		}
		return json.Marshal(securePerson)
	default:
		return nil, errors.New("Unsupported operation")
	}
}

func getHash(body string) string {
	byteBody := []byte(body)
	hash := sha256.New()
	hash.Write(byteBody)
	messageDigest := hash.Sum(nil)
	return hex.EncodeToString(messageDigest)
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func containsData(s []DataEntry, e DataEntry) bool {
	for _, a := range s {
		if a.Key == e.Key {
			return true
		}
	}
	return false
}


func main() {
	err := shim.Start(new(IdentityManagement))
	if err != nil {
		fmt.Printf("Error starting chaincode: %s", err)
	}
}
