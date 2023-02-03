# CSFLE Automatic Encryption skeleton code

import sys
import names
from pymongo.errors import EncryptionError, ServerSelectionTimeoutError, ConnectionFailure
from bson.codec_options import CodecOptions
from pymongo.encryption_options import AutoEncryptionOpts
from bson.binary import STANDARD, Binary, UUID_SUBTYPE
from pymongo import MongoClient
from pprint import pprint
from datetime import datetime


# IN VALUES HERE!
PETNAME = 
MDB_PASSWORD = 

# create our MongoClient with the required attributes, and test the connection
def mdb_client(db_data, auto_encryption_opts=None):
  try:
    client = MongoClient(db_data['DB_CONNECTION_STRING'], serverSelectionTimeoutMS=db_data['DB_TIMEOUT'], tls=True, tlsCAFile=db_data['DB_SSL_CA'], auto_encryption_opts=auto_encryption_opts)
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
  keyvault_db = "__encryption"
  keyvault_coll = "__keyVault"
  keyvault_namespace = f"{keyvault_db}.{keyvault_coll}"

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

  # retrieve the DEK UUID
  data_key_id_1 = client[keyvault_db][keyvault_coll].find_one({"keyAtlName": "dataKey1"},{"_id": 0, "keyAtlName": 1})
  
  encrypted_db_name = "companyData"
  encrypted_coll_name = "employee"
  schema_map = {
    "companyData.employee": {
      "bsonType": "object",
      "encryptMeta": {
        "keyId": data_key_id_1,
        "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512_Random"
      },
      "properties": {
        "name": {
          "bsonType": "object",
          "firstName": {
            "encrypt" : {
              "bsonType": "string",
              "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic"
            }
          },
          "lastName": {
            "encrypt" : {
              "bsonType": "string",
              "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic"
            }
          },
          "otherNames": {
            "encrypt" : {
              "bsonType": "string"
            }
          }
        },
        "address": {
          "encrypt": {
            "bsonType": "object"
          }
        },
        "dob": {
          "encrypt": {
            "bsonType": "datetime"
          }
        },
        "phoneNumber": {
          "encrypt": {
            "bsonType": "string"
          }
        },
        "salary": {
          "encrypt": {
            "bsonType": "double"
          }
        },
        "taxIdentifier": {
          "encrypt": {
            "bsonType": "string"
          }
        }
      }
    }
  }

  auto_encryption = AutoEncryptionOpts(
    kms_provider,
    keyvault_namespace,
    schema_map = {schema_map},
    kms_tls_options = {
      "kmip": {
        "tlsCAFile": "/etc/pki/tls/certs/ca.cert",
        "tlsCertificateKeyFile": "/home/ec2-user/server.pem"
      }
    }
  )

  secure_client, err = mdb_client(config_data, auto_encryption_opts=auto_encryption)
  if err != None:
    print(err)
    sys.exit(1)

  try:

    # PUT CODE HERE TO QUERY THE SALARY FIELD
    decrypted_doc = 

    print(decrypted_doc)
  except EncryptionError as e:
    print(f"Encryption error: {e}")
    sys.exit(1)

  try:

    # PUT CODE HERE TO PERFORM A RANGE QUERY ON THE `name.firstName` field
    decrypted_doc = 

    print(decrypted_doc)
  except EncryptionError as e:
    print(f"Encryption error: {e}")
    sys.exit(1)

if __name__ == "__main__":
  main()