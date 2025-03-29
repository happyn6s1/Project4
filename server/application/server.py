from flask import Flask, request, jsonify
from flask_restful import Resource, Api
# TODO: import additional modules as required
import base64
import json
import secrets
import glob,os
from datetime import datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as aes_padding

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

def check_grant(session_token, DID, mode):
    user = get_userid_from_token(session_token)
    if DID not in acl:
        return False
    current_time = datetime.now()

    for u, r, start, end in acl[DID][::-1]:
        if u == user or u == "0":
            if start <= current_time <= end and r & mode:
                return True
            else:
                return False 
    return False
def hash_data(filedata):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(filedata)
    return digest.finalize()

def encrypt_data(filedata):
    aes_key = secrets.token_bytes(32)
    key = aes_key.hex()
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = aes_padding.PKCS7(128).padder()
    padded_data = padder.update(filedata) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext, aes_key.hex()+":"+iv.hex()

def decrypt_data(encrypted_filedata, hash_key):
    key_hex , iv_hex = hash_key.split(":")
    aes_key = bytes.fromhex(key_hex)
    iv = bytes.fromhex(iv_hex)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted_filedata) + decryptor.finalize()
    unpadder = aes_padding.PKCS7(128).unpadder()
    decrypted_text = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted_text 

def setowner(session_token, DID):
    # access_filename = f"access_{DID}.csv"
    user_id = get_userid_from_token(session_token)
    # with open(access_filename, "w") as f:
    #    f.write(f"{user_id},INF,INF")
    access_map[DID] = [user_id, "", ""]
 
def setattr(DID, securityflag, hashkey):
    # access_filename = f"access_{DID}.csv"
    # with open(access_filename, "w") as f:
    #    f.write(f"{user_id},INF,INF")
    access_map[DID][1] = securityflag
    access_map[DID][2] = hashkey
 
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
            debug()
            return jsonify(response)
        success = verify_statement(statement, signed_statement, user_public_key_file)

        if success:
            session_token = secrets.token_hex()
            # print(session_token)
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
        debug()
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
        # print(data)
        filedata = base64.b64decode(data['filedata'])
        securityflag = data['securityflag']
        DID = data['DID']
        if securityflag not in (1,2):
            response = {
                'status': 700,
                'message': 'Invalid Security Flag',
            }
        filename = f"{project_home}/server/application/documents/{DID}"

        if os.path.exists(filename):
            if checkaccess(token, DID) == "Owner" or check_grant(token, DID, 1):
                pass
            else:
                print("II"*100)
                response = {
                    'status': 702,
                    'message': 'Access denied checking in',
                }
                debug()
                return jsonify(response)
            
        else:
            setowner(token, DID)

        with open(filename, "wb") as f:
            if securityflag == "1":
                # print("encdcccc")
                encrypt_filedata, hash_key = encrypt_data(filedata) 
                f.write(encrypt_filedata)
            else: 
                hash_key = hash_data(filedata) 
                f.write(filedata)
            setattr(DID, securityflag, hash_key)
            #print(access_map) 
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
        debug()
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
        #print(access_map)
        if DID not in access_map or not os.path.exists(f"{project_home}/server/application/documents/{DID}"):
            response = {
                'status': 704,
                'message': 'Check out failed since file not found on the server',
                'file': 'Invalid',
            }
            debug()
            return jsonify(response)
               

        user_id, securityflag, hash_key = access_map[DID]
        if checkaccess(token, DID) or check_grant(token, DID, 2):
            with open(f"{project_home}/server/application/documents/{DID}","rb") as f:
                filedata = f.read()
            success = True
        else:
            success = False
        if success:
            # Similar response format given below can be
            # used for all the other functions
            if securityflag == "1":
                filedata = decrypt_data(filedata, hash_key)
            else:
                hash = hash_data(filedata)
                if hash != hash_key:
                    #print("Integrity check failure")
                    response = {
                        'status': 703,
                        'message': 'Integrity Check Failed',
                        'file': 'Invalid',
                    }
                    debug()
                    return jsonify(response)
                
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
        debug()
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
        DID = data['DID']
        if DID not in access_map or not os.path.exists(f"{project_home}/server/application/documents/{DID}"):
            #print(access_map)
            response = {
                'status': 700,
                'message': 'grant failed since file not found on the server',
                'file': 'Invalid',
            }
            debug()
            return jsonify(response)
        if get_userid_from_token(token) != access_map[DID][0]:
            response = {
                'status': 702,
                'message': 'Access Denied, grant failed since you are not owner',
                'file': 'Invalid',
            }
            debug()
            return jsonify(response)
                 
        user_id = data['user_id']
        right = int(data['right'])
        t = data['t']
        t = int(t)
        current_time = datetime.now()
        endtime = current_time + timedelta(seconds=t) 
        if DID in acl:
            acl[DID].append((user_id, right, current_time, endtime))
        else:
            acl[DID] = [(user_id, right, current_time, endtime)]
        #print(acl)
        success = True 
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
        debug()
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
            debug()
            return jsonify(response)
               
       
        if checkaccess(token, DID) == "Owner":
            os.remove(f"{project_home}/server/application/documents/{DID}")
            if DID in access_map:
                del access_map[DID]
            if DID in acl:
                del acl[DID]
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
                'message': 'Access denied to delete',
                'file': 'Invalid',
            }
        debug()
        return jsonify(response)


class logout(Resource):
    def post(self):
        """
            Expected response status codes:
            1) 200 - Successfully logged out
            2) 700 - Failed to log out
        """

        data = request.get_json()
        token = data['token']
        user = get_userid_from_token(token)
        del tokens[token]
        
        # Similar response format given below can be
        # used for all the other functions
        response = {
            'status': 200,
            'message': 'Successfully logged out',
        }
        debug()
        return jsonify(response)



api.add_resource(welcome, '/')
api.add_resource(login, '/login')
api.add_resource(checkin, '/checkin')
api.add_resource(checkout, '/checkout')
api.add_resource(grant, '/grant')
api.add_resource(delete, '/delete')
api.add_resource(logout, '/logout')

def debug():
    print("====")
    print(tokens)
    print(access_map)
    print(acl)
    print("====")
project_home = "/home/cs6238/Desktop/Project4"
def main():
    secure_shared_service.run(debug=True)

def clearup():
    dir = f"{project_home}/server/application/documents"
    for f in os.listdir(dir):
        fp = os.path.join(dir, f)
        if os.path.isfile(fp):
            os.remove(fp)
if __name__ == '__main__':
    clearup()
    main()
