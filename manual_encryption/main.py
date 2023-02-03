# CSFLE Manual Encryption skeleton code

from pymongo import MongoClient
from pymongo.errors import EncryptionError, ServerSelectionTimeoutError, ConnectionFailure
from bson.codec_options import CodecOptions
from pymongo.encryption.Algorithm import AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic, AEAD_AES_256_CBC_HMAC_SHA_512_Random
from bson.binary import STANDARD, Binary
from pymongo.encryption import ClientEncryption
from datetime import datetime
import sys


# IN VALUES HERE!
PETNAME = 
MDB_PASSWORD = 

# create our MongoClient with the required attributes, and test the connection
def mdb_client(db_data):
  try:
    client = MongoClient(db_data['DB_CONNECTION_STRING'], serverSelectionTimeoutMS=db_data['DB_TIMEOUT'], tls=True, tlsCAFile=db_data['DB_SSL_CA'])
    client.admin.command('hello')
    return client, None
  except (ServerSelectionTimeoutError, ConnectionFailure) as e:
    return None, f"Cannot connect to database, please check settings in config file: {e}"

def main():

  # Obviously this should not be hardcoded
  config_data = {
    "DB_CONNECTION_STRING": f"mongodb://app_user:{MDB_PASSWORD}@csfle-mongodb-{PETNAME}.mdbtraining.net",
    "DB_TIMEOUT": 5000,
    "DB_SSL_CA": "/etc/pki/tls/certs/ca.cert"
  }

  # Declare or key vault namespce
  keyvault_namespace = f"__encryption.__keyVault"

  # declare our key provider type
  provider = "kmip"

  # declare our key provider attributes
  kms_provider = {
    provider: {
      "endpoint": f"csfle-kmip-{PETNAME}.mdbtraining.net"
    }
  }
  
  # declare our database and collection
  encrypted_db_name = "companyData"
  encrypted_coll_name = "employee"

  # instantiate our MongoDB Client object
  client, err = mdb_client(config_data)
  if err != None:
    print(err)
    sys.exit(1)


  # Instantiate our ClientEncryption object
  client_encryption = ClientEncryption(
    kms_provider,
    keyvault_namespace,
    client,
    CodecOptions(uuid_representation=STANDARD),
    kms_tls_options = {
      "kmip": {
        "tlsCAFile": "/etc/pki/tls/certs/ca.cert",
        "tlsCertificateKeyFile": "/home/ec2-user/server.pem"
      }
    }
  )

  payload = {
    "name": {
      "firstName": "Manish",
      "lastName": "Engineer",
      "otherNames": None,
    },
    "address": {
      "streetAddress": "1 Bson Street",
      "suburbCounty": "Mongoville",
      "stateProvince": "Victoria",
      "zipPostcode": "3999",
      "country": "Oz"
    },
    "dob": datetime(1980, 10, 10),
    "phoneNumber": "1800MONGO",
    "salary": 999999.99,
    "taxIdentifier": "78SD20NN001",
    "role": [
      "CTO"
    ]
  }

  try:

    # retrieve the DEK UUID
    data_key_id_1 = # Put code here to find the _id of the DEK we created previously
    if data_key_id_1 is None:
      print("Failed to find DEK")
      sys.exit()

    # WRITE CODE HERE TO ENCRYPT THE APPROPRIATE FIELDS
    # Don't forget to handle to event of name.otherNames being null


    # Test if the data is encrypted
    for data in [ payload["name"]["firstName"], payload["name"]["lastName"], payload["address"], payload["dob"], payload["phoneNumber"], payload["salary"], payload["taxIdentifier"]]:
      if type(data) is not Binary and data.subtype != 6:
        print("Data is not encrypted")
        sys.exit()

  except EncryptionError as e:
    print(f"Encryption error: {e}")


  print(payload)

  result = client[encrypted_db_name][encrypted_coll_name].insert_one(payload)

  print(result.inserted_id)

if __name__ == "__main__":
  main()