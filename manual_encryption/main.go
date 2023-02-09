package main

import (
	"C"
	"context"
	"fmt"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	PETNAME = 
	MDB_PASSWORD =
)

type SchemaObject struct {
	deterministic [][]string
	random        [][]string
}

func createClient(c string) (*mongo.Client, error) {
	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(c))

	if err != nil {
		return nil, err
	}

	return client, nil
}

func createManualEncryptionClient(c *mongo.Client, kp map[string]map[string]interface{}, kns string) (*mongo.ClientEncryption, error) {
	o := options.ClientEncryption().SetKeyVaultNamespace(kns).SetKmsProviders(kp)
	client, err := mongo.NewClientEncryption(c, o)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func encryptManual(ce *mongo.ClientEncryption, dek primitive.Binary, alg string, data interface{}) (primitive.Binary, error) {
	var out primitive.Binary
	rawValueType, rawValueData, err := bson.MarshalValue(data)
	if err != nil {
		return primitive.Binary{}, err
	}

	rawValue := bson.RawValue{Type: rawValueType, Value: rawValueData}

	encryptionOpts := options.Encrypt().
		SetAlgorithm(alg).
		SetKeyID(dek)

	out, err = // PUT CODE HERE TO MANUALLY ENCRYPT
	if err != nil {
		return primitive.Binary{}, err
	}

	return out, nil
}

func main() {
	var (
		keyVaultDB 			 = "__encryption"
		keyVaultColl 		 = "__keyVault"
		keySpace         = keyVaultDB + "." + keyVaultColl
		connectionString = "mongodb://app_user:" + MDB_PASSWORD + "@csfle-mongodb-" + PETNAME + ".mdbtraining.net/?replicaSet=rs0&tls=true&tlsCAFile=%2Fetc%2Fpki%2Ftls%2Fcerts%2Fca.cert"
		kmipEndpoint     = "csfle-kmip-" + PETNAME + ".mdbtraining.net"
		clientEncryption *mongo.ClientEncryption
		client           *mongo.Client
		exitCode         = 0
		result           *mongo.InsertOneResult
		dekFindResult    bson.M
		dek              primitive.Binary
		err							 error
	)

	defer func() {
		os.Exit(exitCode)
	}()

	provider := "kmip"
	kmsProvider := map[string]map[string]interface{}{
		provider: {
			"endpoint": kmipEndpoint,
		},
	}
	client, err = createClient(connectionString)
	if err != nil {
		fmt.Printf("MDB client error: %s\n", err)
		exitCode = 1
		return
	}

	coll := client.Database("__encryption").Collection("__keyVault")

	clientEncryption, err = createManualEncryptionClient(client, kmsProvider, keySpace)
	if err != nil {
		fmt.Printf("ClientEncrypt error: %s\n", err)
		exitCode = 1
		return
	}

	payload := bson.M{
    "name": bson.M{
      "firstName": "Manish",
      "lastName": "Engineer",
      "otherNames": nil,
    },
    "address": bson.M{
      "streetAddress": "1 Bson Street",
      "suburbCounty": "Mongoville",
      "stateProvince": "Victoria",
      "zipPostcode": "3999",
      "country": "Oz",
    },
    "dob": time.Date(1980, 10, 10, 0, 0, 0, 0, time.Local),
    "phoneNumber": "1800MONGO",
    "salary": 999999.99,
    "taxIdentifier": "78SD20NN001",
    "role": []string{"CTO"},
  }

	// Retrieve our DEK
	opts := options.FindOne().SetProjection(bson.D{{Key: "_id", Value: 1}})
	err = coll.FindOne(context.TODO(), bson.D{// Put your DEK query here}, opts).Decode(&dekFindResult)
	if err != nil || len(dekFindResult) == 0 {
		fmt.Printf("DEK find error: %s\n", err)
		exitCode = 1
		return
	}
	dek = dekFindResult["_id"].(primitive.Binary)

	//  WRITE CODE HERE TO ENCRYPT THE APPROPRIATE FIELDS with the encryptManual() function above
	// Don't forget to handle to event of name.otherNames being null

	coll = client.Database("companyData").Collection("employee")

	result, err = coll.InsertOne(context.TODO(), payload)
	if err != nil {
		fmt.Printf("Insert error: %s\n", err)
		exitCode = 1
		return
	}
	fmt.Print(result.InsertedID)

	exitCode = 0
}