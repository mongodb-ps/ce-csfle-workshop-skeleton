try:
  from os import path
  from sys import version_info
  from bson.binary import STANDARD, Binary, UUID_SUBTYPE
  from bson.codec_options import CodecOptions
  from datetime import datetime
  from pprint import pprint
  from pymongo import MongoClient
  from pymongo.encryption import Algorithm
  from pymongo.encryption import ClientEncryption
  from pymongo.encryption_options import AutoEncryptionOpts
  from pymongo.errors import EncryptionError, ServerSelectionTimeoutError, ConnectionFailure
  from random import randint
  from urllib.parse import quote_plus
  import names
  import sys
except ImportError as e:
  print(f"Import error for {path.basename(__file__)}: {e}")
  exit(1)


# IN VALUES HERE!
PETNAME = 
MDB_PASSWORD = 
APP_USER = "app_user"
CA_PATH = "/etc/pki/tls/certs/ca.cert"

def check_python_version() -> str | None:
  """Checks if the current Python version is supported.

  Returns:
    A string indicating that the current Python version is not supported, or None if the current Python version is supported.
  """
  if version_info.major < 3 or (version_info.major == 3 and version_info.minor < 10):
    return f"Python version {version_info.major}.{version_info.minor} is not supported, please use 3.10 or higher"
  return None

def mdb_client(connection_string: str, auto_encryption_opts: tuple[dict | None] = None) -> tuple[MongoClient | None, str | None]:
  """ Returns a MongoDB client instance
  
  Creates a  MongoDB client instance and tests the client via a `hello` to the server
  
  Parameters
  ------------
    connection_string: string
      MongoDB connection string URI containing username, password, host, port, tls, etc
  Return
  ------------
    client: mongo.MongoClient
      MongoDB client instance
    err: error
      Error message or None of successful
  """

  try:
    client = MongoClient(connection_string, auto_encryption_opts=auto_encryption_opts)
    client.admin.command('hello')
    return client, None
  except (ServerSelectionTimeoutError, ConnectionFailure) as e:
    return None, f"Cannot connect to database, please check settings in config file: {e}"

def get_employee_key(client: MongoClient, altName: str, provider_name: str, keyId: str) -> tuple[str | None, str | None]:
  """ Return a DEK's UUID for a give KeyAltName. Creates a new DEK if the DEK is not found.
  
  Queries a key vault for a particular KeyAltName and returns the UUID of the DEK, if found.
  If not found, the UUID and Key Provider object and CMK ID are used to create a new DEK

  Parameters
  -----------
    client: mongo.ClientEncryption
      An instantiated ClientEncryption instance that has access to the key vault
    altName: string
      The KeyAltName of the UUID to find
    provider_name: string
      The name of the key provider. "aws", "gcp", "azure", "kmip", or "local"
    keyId: string
      The key ID for the Customer Master Key (CMK)
  Return
  -----------
    employee_key_id: UUID
      The UUID of the DEK
    error: error
      Error message or None of successful
  """
  
  employee_key_id = client.get_key_by_alt_name(str(altName))
  if employee_key_id == None:
    try:
      master_key = {"keyId": keyId, "endpoint": f"csfle-kmip-{PETNAME}.mdbtraining.net"}
      employee_key_id = client.create_data_key(kms_provider=provider_name, master_key=master_key, key_alt_names=[str(altName)])
    except EncryptionError as e:
      return None, f"ClientEncryption error: {e}"
  else:
    employee_key_id = employee_key_id["_id"]
  return employee_key_id, None

def main():

  # check version of Python is correct
  err = check_python_version()
  if err is not None:
    print(err)
    exit(1)

  # Obviously this should not be hardcoded
  connection_string = "mongodb://%s:%s@csfle-mongodb-%s.mdbtraining.net/?serverSelectionTimeoutMS=5000&tls=true&tlsCAFile=%s" % (
    quote_plus(APP_USER),
    quote_plus(MDB_PASSWORD),
    PETNAME,
    quote_plus(CA_PATH)
  )

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
  client, err = mdb_client(connection_string)
  if err is not None:
    print(err)
    sys.exit(1)

  # Create ClientEncryption instance for creating DEks and manual encryption
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

  employee_id = str("%05d" % randint(0,99999))
  firstname = names.get_first_name()
  lastname = names.get_last_name()

  # PUT CODE HERE TO RETRIEVE OUR COMMON (our first) DEK:
  data_key_id_1 = client[keyvault_db][keyvault_coll].find_one({"keyAltNames": "dataKey1"},{"_id": 1})["_id"]
  if data_key_id_1 is None:
    print("Common DEK missing")
    sys.exit(1)

  # retrieve the DEK UUID
  _, err = get_employee_key(client_encryption, employee_id, provider, '1')
  if err is not None:
    print(err)
    sys.exit(1)

  payload = {
    "_id": employee_id,
    "name": {
      "firstName": firstname,
      "lastName": lastname,
      "otherNames": None,
    },
    "address": {
      "streetAddress": "3 Bson Street",
      "suburbCounty": "Mongoville",
      "stateProvince": "Victoria",
      "zipPostcode": "3999",
      "country": "Oz"
    },
    "dob": datetime(1978, 10, 10),
    "phoneNumber": "1800MONGO",
    "salary": 999999.99,
    "taxIdentifier": "78SD20NN001",
    "role": [
      "CIO"
    ]
  }

  encrypted_db_name = "companyData"
  encrypted_coll_name = "employee"
  schema_map = {
    "companyData.employee": {
      "bsonType": "object",
      "encryptMetadata": {
        "keyId": , # PUT APPROPRIATE CODE OR VARIABLE HERE
        "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
      },
      "properties": {
        "name": {
          "bsonType": "object",
          "properties": {
            "firstName": {
              "encrypt" : {
                "keyId": , # PUT COMMON KEY UUID HERE
                "bsonType": "string",
                "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
              }
            },
            "lastName": {
              "encrypt" : {
                "keyId": , # PUT COMMON KEY UUID HERE
                "bsonType": "string",
                "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
              }
            },
            "otherNames": {
              "encrypt" : {
                "bsonType": "string"
              }
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
            "bsonType": "date"
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
    schema_map = schema_map,
    kms_tls_options = {
      "kmip": {
        "tlsCAFile": "/etc/pki/tls/certs/ca.cert",
        "tlsCertificateKeyFile": "/home/ec2-user/server.pem"
      }
    },
    crypt_shared_lib_required = True,
    mongocryptd_bypass_spawn = True,
    crypt_shared_lib_path = '/lib/mongo_crypt_v1.so'
  )

  secure_client, err = mdb_client(connection_string, auto_encryption_opts=auto_encryption)
  if err is not None:
    print(err)
    sys.exit(1)
  encrypted_db = secure_client[encrypted_db_name]

  # remove `name.otherNames` if None because wwe cannot encrypt none
  if payload["name"]["otherNames"] == None:
    del(payload["name"]["otherNames"])

  try:
    result = encrypted_db[encrypted_coll_name].insert_one(payload)
    print(result.inserted_id)
  except EncryptionError as e:
    print(f"Encryption error: {e}")
    sys.exit(1)

  try: 
    result = encrypted_db[encrypted_coll_name].find_one({"name.firstName": firstname, "name.lastName": lastname})
  except EncryptionError as e:
    print(f"Encryption error: {e}")
    sys.exit(1)

  pprint(result)

if __name__ == "__main__":
  main()