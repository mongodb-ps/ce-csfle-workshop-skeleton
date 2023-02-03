# CSFLE Manual Encryption skeleton code

from pymongo import MongoClient
from pymongo.errors import EncryptionError, ServerSelectionTimeoutError, ConnectionFailure
from bson.codec_options import CodecOptions
from bson.binary import Binary
from pymongo.encryption.Algorithm import AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic, AEAD_AES_256_CBC_HMAC_SHA_512_Random
from bson.binary import STANDARD
from pymongo.encryption import ClientEncryption
from pymongo.encryption_options import AutoEncryptionOpts
from datetime import datetime
import sys


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

# test if we have a binary value with subtype 6, if true this is encrypted data, therefore decrypt it
def decrypt_data(client_encryption, data):
  try:
    if type(data) == Binary and data.subtype == 6:

      # PUT YOUR DECRYPTION CODE HERE
      decrypted_data = 

      return decrypted_data
    else:
      return data
  except EncryptionError as e:
    raise e

# traverse the whole BSON document, call the decrypt function when we have scalar values
def transverse_bson(client_encryption, data):
  if isinstance(data, list):
    return [transverse_bson(client_encryption, v) for v in data]
  elif isinstance(data, dict):
    return {k: transverse_bson(client_encryption, v) for k, v in data.items()}
  else:
    return decrypt_data(client_encryption, data)

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

  auto_encryption = AutoEncryptionOpts(
    kms_provider,
    keyvault_namespace,
    schema_map = , # WHAT DO WE PUT HERE?
    bypass_auto_encrpytion = True, # we do not want to autoencrypt
    kms_tls_options = {
      "kmip": {
        "tlsCAFile": "/etc/pki/tls/certs/ca.cert",
        "tlsCertificateKeyFile": "/home/ec2-user/server.pem"
      }
    }
  )

  encrypted_client, err = mdb_client(config_data, auto_encryption)
  if err != None:
    print(err)
    sys.exit(1)

  payload = {
    "name": {
      "firstName": "Poorna",
      "lastName": "Muggle",
      "otherNames": None,
    },
    "address": {
      "streetAddress": "29 Bson Street",
      "suburbCounty": "Mongoville",
      "stateProvince": "Victoria",
      "zipPostcode": "3999",
      "country": "Oz"
    },
    "dob": datetime(1999, 1, 12),
    "phoneNumber": "1800MONGO",
    "salary": 999999.99,
    "taxIdentifier": "78SDSSWN001",
    "role": [
      "CE"
    ]
  }

  try:

    # Retrieve the DEK UUID
    data_key_id_1 = client_encryption.get_key_by_alt_name("dataKey1")["_id"]

    # Do deterministic fields
    payload["name"]["firstName"] = client_encryption.encrypt(payload["name"]["firstName"], AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic, data_key_id_1)
    payload["name"]["lastName"] = client_encryption.encrypt(payload["name"]["lastName"], AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic, data_key_id_1)

    # Do random fields
    payload["name"]["otherNames"] = client_encryption.encrypt(payload["name"]["otherNames"], AEAD_AES_256_CBC_HMAC_SHA_512_Random, data_key_id_1)
    payload["address"] = client_encryption.encrypt(payload["AEAD_AES_256_CBC_HMAC_SHA_512_Random"], AEAD_AES_256_CBC_HMAC_SHA_512_Random, data_key_id_1)
    payload["dob"] = client_encryption.encrypt(payload["dob"], AEAD_AES_256_CBC_HMAC_SHA_512_Random, data_key_id_1)
    payload["phoneNumber"] = client_encryption.encrypt(payload["phoneNumber"], AEAD_AES_256_CBC_HMAC_SHA_512_Random, data_key_id_1)
    payload["salary"] = client_encryption.encrypt(payload["salary"], AEAD_AES_256_CBC_HMAC_SHA_512_Random, data_key_id_1)
    payload["taxIdentifier"] = client_encryption.encrypt(payload["taxIdentifier"], AEAD_AES_256_CBC_HMAC_SHA_512_Random, data_key_id_1)

    result = client[encrypted_db_name][encrypted_coll_name].insert_one(payload)

    print(result.inserted_id)

    # Encrypted data to query 
    name =  client_encryption.encrypt("Poorna", AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic, data_key_id_1)

  except EncryptionError as e:
    print(f"Encryption error: {e}")
    sys.exit()

  # PUT CODE HERE TO RETRIEVE AND AUTOMATICALLY DECRYPT THE DOCUMENT
  encrypted_doc = 

  print(encrypted_doc)



if __name__ == "__main__":
  main()