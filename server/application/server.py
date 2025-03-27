from flask import Flask, request, jsonify
from flask_restful import Resource, Api
# TODO: import additional modules as required
import base64
import json
import secrets
import glob,os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

secure_shared_service = Flask(__name__)
api = Api(secure_shared_service)

#use a map to store session to user mapping
tokens = {}
#use a map to store file DID to owner, securityflag, and key/hash 
access_map = {}
#use a map to store file DID to a list of ACLs [starttime, endtime]
acl = {}

def save_session_token(session_token, user_id):
    # session_filename = f"session_{user_id}.txt"
    # with open(session_filename, "w") as f:
    #    f.write(session_token)
    tokens[session_token] = user_id

def get_userid_from_token(session_token):
    # files = glob.glob("session_*.txt")
    # for fn in files:
    #    with open(fn) as f:
    #        if session_token == f.readline():
    #            return fn[8:-4]
    # return None
    if session_token in tokens:
        return tokens[session_token]
    else:
        return None

def checkaccess(session_token, DID):
    # access_filename = f"access_{DID}.csv"
    user = get_userid_from_token(session_token)
    # with open(access_filename) as f:
    #    for line in f.readlines():
    #        user_id, start, end = line.strip().split(",")
    #        if start == "INF" and end == "INF" and user_id == user:
    #            return "Owner"         
    # return "" 
    if DID in access_map and access_map[DID][0] == user:
        return "Owner"
    return ""
def hash_data(filedata):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(filedata)
    return digest.finalize()

def encrypt_data(filedata):
    aes_key = secrets.token_bytes(32)
    key = aes_key.hex()
    iv = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(aes_key). modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(filedata) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext, aes_key.hex()+":"+iv.hex()

def decrypt_data(encrypted_filedata, hash_key):
    key_hex , iv_hex = hash_key.split(":")
    key = bytes.fromhex(key_hex)
    iv = bytes.fromhex(iv_hex)
    cipher = Cipher(algorithms.AES(aes_key). modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finilize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_text = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted_text 

def setattr(session_token, DID, securityflag, hashkey):
    # access_filename = f"access_{DID}.csv"
    user_id = get_userid_from_token(session_token)
    # with open(access_filename, "w") as f:
    #    f.write(f"{user_id},INF,INF")
    access_map[DID] = [user_id, securityflag, hashkey]
 
class welcome(Resource):
    def get(self):
        return "Welcome to the secure shared server!"

def verify_statement(statement, signed_statement, user_public_key_file):
    with open(user_public_key_file, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
        )
        try:
            public_key.verify(
                signed_statement,
                statement.encode("utf-8"),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except:
            return False
        return True 


class login(Resource):
    def post(self):
        data = request.get_json()
        # TODO: Implement login functionality
        '''
            # TODO: Verify the signed statement.
            Response format for success and failure are given below. The same
            keys ('status', 'message', 'session_token') should be used.
            Expected response status codes:
            1) 200 - Login Successful
            2) 700 - Login Failed
        '''
        # Information coming from the client
        user_id = data['user-id']
        statement = data['statement']
        signed_statement = base64.b64decode(data['signed-statement'])

        # complete the full path of the user public key filename
        # /home/cs6238/Desktop/Project4/server/application/userpublickeys/{user_public_key_filename}
        user_public_key_file = f"{project_home}/server/application/userpublickeys/{user_id}.pub"
        if not os.path.exists(user_public_key_file):
            response = {
                'status': 701,
                'message': f"Login Failed - Cannot find public key file {user_public_key_file}",
                'session_token': "INVALID",
            }
            return jsonify(response)
        success = verify_statement(statement, signed_statement, user_public_key_file)

        if success:
            session_token = secrets.token_hex()
            print(session_token)
            save_session_token(session_token, user_id)
            # Similar response format given below can be used for all the other functions
            response = {
                'status': 200,
                'message': 'Login Successful',
                'session_token': session_token,
            }
        else:
            response = {
                'status': 700,
                'message': 'Login Failed',
                'session_token': "INVALID",
            }
        return jsonify(response)


class checkin(Resource):
    """
    Expected response status codes:
    1) 200 - Document Successfully checked in
    2) 702 - Access denied checking in
    3) 700 - Other failures
    """

    def post(self):
        data = request.get_json()
        token = data['token']
        print(data)
        filedata = base64.b64decode(data['filedata'])
        securityflag = data['securityflag']
        DID = data['DID']
        if securityflag not in (1,2):
            response = {
                'status': 700,
                'message': 'Invalid Security Flag',
            }
            
        with open(f"{project_home}/server/application/documents/{DID}", "wb") as f:
            if securityflag == 1:
                encrypt_filedata, hash_key = encrypt_data(filedata) 
                f.write(encrypt_filedata)
            else: 
                hash_key = hash_data(filedata) 
                f.write(filedata)
            setattr(token, DID, securityflag, hash_key)
            print(access_map) 
        success = True
        if success:
            response = {
                'status': 200,
                'message': 'Document Successfully checked in',
            }
        else:
            response = {
                'status': 702,
                'message': 'Access denied checking in',
            }
        return jsonify(response)


class checkout(Resource):
    """
    Expected response status codes
    1) 200 - Document Successfully checked out
    2) 702 - Access denied checking out
    3) 703 - Check out failed due to broken integrity
    4) 704 - Check out failed since file not found on the server
    5) 700 - Other failures
    """
    def post(self):
        data = request.get_json()
        token = data['token']
        DID = data['DID']
        filedata = ''
        print(access_map)
        if DID not in access_map or not os.path.exists(f"{project_home}/server/application/documents/{DID}"):
            response = {
                'status': 704,
                'message': 'Check out failed since file not found on the server',
                'file': 'Invalid',
            }
            return jsonify(response)
               

        user_id, securityflag, hash_key = access_map[DID]
        if checkaccess(token, DID):
            with open(f"{project_home}/server/application/documents/{DID}","rb") as f:
                filedata = f.read()
            success = True
        else:
            success = False
        if success:
            # Similar response format given below can be
            # used for all the other functions
            if securityflag == 1:
                filedata = decrypt_data(filedata, key_hex)
            response = {
                'status': 200,
                'message': 'Document Successfully checked out',
                'file': base64.b64encode(filedata).decode("utf-8"),
            }
        else:
            response = {
                'status': 702,
                'message': 'Access denied checking out',
                'file': 'Invalid',
            }
        return jsonify(response)

class grant(Resource):
    """
        Expected response status codes:
        1) 200 - Successfully granted access
        2) 702 - Access denied to grant access
        3) 700 - Other failures
    """
    def post(self):
        data = request.get_json()
        token = data['token']
        success = False
        if success:
            # Similar response format given below can be
            # used for all the other functions
            response = {
                'status': 200,
                'message': 'Successfully granted access',
            }
        else:
            response = {
                'status': 702,
                'message': 'Access denied to grant access',
            }
        return jsonify(response)


class delete(Resource):
    """
        Expected response status codes:
        1) 200 - Successfully deleted the file
        2) 702 - Access denied deleting file
        3) 704 - Delete failed since file not found on the server
        4) 700 - Other failures
    """
    def post(self):
        data = request.get_json()
        token = data['token']
        DID = data['DID']
        filedata = ''
        if not os.path.exists(f"{project_home}/server/application/documents/{DID}"):
            response = {
                'status': 704,
                'message': 'Delete failed since file not found on the server',
                'file': 'Invalid',
            }
            return jsonify(response)
               

        if checkaccess(token, DID) == "Owner":
            os.remove(f"{project_home}/server/application/documents/{DID}")
            success = True
        else:
            success = False
        if success:
            # Similar response format given below can be
            # used for all the other functions
            response = {
                'status': 200,
                'message': 'Document Successfully delete',
            }
        else:
            response = {
                'status': 702,
                'message': 'Access denied checking out',
                'file': 'Invalid',
            }
        return jsonify(response)


class logout(Resource):
    def post(self):
        """
            Expected response status codes:
            1) 200 - Successfully logged out
            2) 700 - Failed to log out
        """

        def post(self):
            data = request.get_json()
            token = data['token']
        success = False
        if success:
            # Similar response format given below can be
            # used for all the other functions
            response = {
                'status': 200,
                'message': 'Successfully logged out',
            }
        else:
            response = {
                'status': 700,
                'message': 'Failed to log out',
            }
        return jsonify(response)



api.add_resource(welcome, '/')
api.add_resource(login, '/login')
api.add_resource(checkin, '/checkin')
api.add_resource(checkout, '/checkout')
api.add_resource(grant, '/grant')
api.add_resource(delete, '/delete')
api.add_resource(logout, '/logout')


project_home = "/home/cs6238/Desktop/Project4"
def main():
    secure_shared_service.run(debug=True)


if __name__ == '__main__':
    main()
