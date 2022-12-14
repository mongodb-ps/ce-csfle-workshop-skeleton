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
    "DB_CONNECTION_STRING": "mongodb://app_user:<PASSWORD>@csfle-mongodb-<PETNAME>.mdbtraining.net",
    "DB_TIMEOUT": 5000,
    "DB_SSL_CA": "/etc/pki/tls/certs/ca.cert"
  }


  keyvault_namespace = f"__encryption.__keyVault"
  provider = "kmip"

  kms_provider = {
    provider: {
      "endpoint": "csfle-kmip-<PETNAME>.mdbtraining.net"
    }
  }


  client, err = mdb_client(config_data)
  if err != None:
    print(err)
    sys.exit(1)

  # retrieve the DEK UUID
  data_key_id_1 = # Put code here to find the _id of the DEK we created previously
  
  encrypted_db_name = "companyData"
  encrypted_coll_name = "employee"
  schema_map = { #create your schema map here 
  }

  auto_encryption = AutoEncryptionOpts(
    kms_provider,
    keyvault_namespace,
    schema_map = schema_map,
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
  encrypted_db = secure_client[encrypted_db_name]

  firstname = names.get_first_name()
  lastname = names.get_last_name()
  payload = {
    "name": {
      "firstName": firstname,
      "lastName": lastname,
      "otherNames": None,
    },
    "address": {
      "streetAddress": "2 Bson Street",
      "suburbCounty": "Mongoville",
      "stateProvince": "Victoria",
      "zipPostcode": "3999",
      "country": "Oz"
    },
    "dob": datetime(1980, 10, 11),
    "phoneNumber": "1800MONGO",
    "salary": 999999.99,
    "taxIdentifier": "78SD20NN001",
    "role": [
      "CIO"
    ]
  }

  # remove `name.otherNames` if None because wwe cannot encrypt none
  # Put code here to handle this situation

  try:
    result = encrypted_db[encrypted_coll_name].insert_one(payload)
    print(result.inserted_id)
  except EncryptionError as e:
    print(f"Encryption error: {e}")
    sys.exit(1)

if __name__ == "__main__":
  main()