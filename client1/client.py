import requests
import base64
import json
import shutil
# TODO: import additional modules as required
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

gt_username = 'hjiang365'   # TODO: Replace with your gt username within quotes
server_name = 'secure-shared-store'

# These need to be created manually before you start coding.
# these will be overwritten later

node_certificate = 'clientX.crt'
node_key = 'clientX.key'
checkout_files = {}

''' <!!! DO NOT MODIFY THIS FUNCTION !!!>'''
def post_request(server_name, action, body, node_certificate, node_key):
    """
        node_certificate is the name of the certificate file of the client node (present inside certs).
        node_key is the name of the private key of the client node (present inside certs).
        body parameter should in the json format.
    """
    request_url = 'https://{}/{}'.format(server_name, action)
    request_headers = {
        'Content-Type': "application/json"
    }
    response = requests.post(
        url=request_url,
        data=json.dumps(body),
        headers=request_headers,
        cert=(node_certificate, node_key),
        verify="/home/cs6238/Desktop/Project4/CA/CA.crt",
        timeout=(10, 20),
    )
    with open(gt_username, 'wb') as f:
        f.write(response.content)

    return response

''' You can begin modification from here'''

def sign_statement(statement, user_private_key_file):
    # print(user_private_key_file)
    # print(statement)

    with open(user_private_key_file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
        return private_key.sign(
            statement.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

def login():
    """
        # TODO: Accept the
         - user-id
         - name of private key file(should be present in the userkeys folder) of the user.
        Generate the login statement as given in writeup and its signature.
        Send request to server with required parameters (Ex: action = 'login') using the
        post_request function given.
        The request body should contain the user-id, statement and signed statement.
    """

    successful_login = False
    while not successful_login:
        # get the user id from the user input or default to user1
        user_id = (input(" User Id: ") or "user1")

        # get the user private key filename or default to user1.key
        private_key_filename = (input(" Private Key Filename: ") or "user1.key")

        # complete the full path of the user private key filename (depends on the client)
        # Ex: '/home/cs6238/Desktop/Project4/client1/userkeys/' + private_key_filename
        user_private_key_file = f"{project_home}/{clientID}/userkeys/"+ private_key_filename
        if not os.path.exists(user_private_key_file):
            print(f"\nUser Private Key File Does not exist:\n{user_private_key_file}")
            return None
        # create the statement
        statement = f"{clientID} as {user_id} logs into the Server"
        signed_statement = sign_statement(statement, user_private_key_file)
        # print(base64.b64encode(signed_statement).decode("utf8"))

        body = {
            'user-id': user_id,
            'statement': statement,
            'signed-statement': base64.b64encode(signed_statement).decode("utf8")
        }

        server_response = post_request(server_name, 'login', body, node_certificate, node_key)
        # print(server_response.json())
        if server_response.json().get('status') == 200:
            print(f"{user_id} login Succesfully")
            successful_login = True
        else:
            print(server_response.json().get('message', "Try again"))
    #print(server_response.json())
    return server_response.json()


def checkin(session_token):
    """
        # TODO: Accept the
         - DID: document id (filename)
         - security flag (1 for confidentiality  and 2 for integrity)
        Send the request to server with required parameters (action = 'checkin') using post_request().
        The request body should contain the required parameters to ensure the file is sent to the server.
    """
    DID = (input(" Document Id: ") or "file1.txt")
    flag = (input(" Security Flag: ") or "1")
    src = f"/home/cs6238/Desktop/Project4/{clientID}/documents/checkout/{DID}"    
    if DID in checkout_files and os.path.exists(src):
        del checkout_files[DID]
        dest = f"/home/cs6238/Desktop/Project4/{clientID}/documents/checkin/{DID}"
        shutil.move(src,dest)
    file_home = f"/home/cs6238/Desktop/Project4/{clientID}/documents/checkin"    
    # validate the flag
    file = f"{file_home}/{DID}"
    if not os.path.exists(file):
        print(f"\nFile Does not exist: {file}")
        return None
    checkin_file(DID, file, flag, session_token)

def checkin_file(DID, file, flag, session_token):
    filedata = ""
    with open(file,"rb") as f:
        filedata = f.read()
    body = {
        'token': session_token,
        'DID': DID,
        'securityflag': flag,
        'filedata': base64.b64encode(filedata).decode("utf-8")
    }
    server_response = post_request(server_name, 'checkin', body, node_certificate, node_key)
    # print(server_response.json())
    if server_response.json().get('status') == 200:
        print(f"Check In Succesfully: {file} with security flag {flag}")
    else:
        print(server_response.json().get('message', "Try again"))
    return


def checkout(session_token):
    """
        # TODO:
        Send request to server with required parameters (action = 'checkout') using post_request()
    """
    DID = (input(" Document Id: ") or "file1.txt")
    # validate the flag
    file_home = f"/home/cs6238/Desktop/Project4/{clientID}/documents/checkout"    
    filedata = ""
    body = {
        'token': session_token,
        'DID': DID,
    }
    server_response = post_request(server_name, 'checkout', body, node_certificate, node_key)
    #print(server_response.json())
    if server_response.json().get('status') == 200:
        with open(f"{file_home}/{DID}", "wb") as f:
            f.write(base64.b64decode(server_response.json().get('file')))
        print(f"checkout succesfully for file {DID}")
        checkout_files[DID] = True
    else:
        print(server_response.json().get('message', "Try again"))
    
    return


def grant(session_token):
    """
        # TODO:
         - DID
         - target user to whom access should be granted (0 for all user)
         - type of access to be granted (1 - checkin, 2 - checkout, 3 - both checkin and checkout)
         - time duration (in seconds) for which access is granted
        Send request to server with required parameters (action = 'grant') using post_request()
    """
    DID = (input(" Document Id: ") or "file1.txt")
    user_id = (input(" Target User Id: ") or "user1")
    right  = (input(" Access Right: ") or "1")
    t = (input(" Time in seconds: ") or "60")
    # validate the flag
    body = {
        'token': session_token,
        'DID': DID,
        'user_id': user_id,
        'right': right,
        't': t,
    }
    server_response = post_request(server_name, 'grant', body, node_certificate, node_key)
    # print(server_response.json())
    if server_response.json().get('status') == 200:
        print(f"Granted file {DID} to {user_id} for {t} seconds with right : {right}")
    else:
        print(server_response.json().get('message', "Try again"))
    
    return



    return


def delete(session_token):
    """
        # TODO:
        Send request to server with required parameters (action = 'delete')
        using post_request().
    """
    DID = (input(" Document Id: ") or "file1.txt")
    # validate the flag
    body = {
        'token': session_token,
        'DID': DID,
    }
    server_response = post_request(server_name, 'delete', body, node_certificate, node_key)
    #print(server_response.json())
    if server_response.json().get('status') == 200:
        print(f"The File {DID} has been Deleted")
        del checkout_files[DID]
    else:
        print(server_response.json().get('message', "Try again"))
    
    return





def logout(session_token):
    """
        # TODO: Ensure all the modified checked out documents are checked back in.
        Send request to server with required parameters (action = 'logout') using post_request()
        The request body should contain the user-id, session-token
    """
    for DID in checkout_files:
        flag = 2
        src = f"/home/cs6238/Desktop/Project4/{clientID}/documents/checkout/{DID}"    
        if os.path.exists(src):
            dest = f"/home/cs6238/Desktop/Project4/{clientID}/documents/checkin/{DID}"
            shutil.move(src,dest)
            file_home = f"/home/cs6238/Desktop/Project4/{clientID}/documents/checkin"    
            checkin_file(DID, dest, flag, session_token)

    body = {
        'token': session_token,
    }
    server_response = post_request(server_name, 'logout', body, node_certificate, node_key)
    print(server_response.json())
    if server_response.json().get('status') == 200:
        print(f"Logout succesfully")
    else:
        print(server_response.json().get('message', "Try again"))
    
    is_login = False
    return


def print_main_menu():
    """
    print main menu
    :return: nothing
    """
    print(" Enter Option: ")
    print("    1. Checkin")
    print("    2. Checkout")
    print("    3. Grant")
    print("    4. Delete")
    print("    5. Logout")
    return


def main():
    """
        # TODO: Authenticate the user by calling login.
        If the login is successful, provide the following options to the user
            1. Checkin
            2. Checkout
            3. Grant
            4. Delete
            5. Logout
        The options will be the indices as shown above. For example, if user
        enters 1, it must invoke the Checkin function. Appropriate functions
        should be invoked depending on the user input. Users should be able to
        perform these actions in a loop until they logout. This mapping should
        be maintained in your implementation for the options.
    """

    # Initialize variables to keep track of progress
    server_message = 'UNKNOWN'
    server_status = 'UNKNOWN'
    session_token = 'UNKNOWN'
    is_login = False

    # test()
    # return
    login_return = login()
    if not login_return:
        return
 
    server_message = login_return['message']
    server_status = login_return['status']
    session_token = login_return['session_token']

    print("\nThis is the server response")
    print(server_message)
    print(server_status)
    print(session_token)

    if server_status == 200:
        is_login = True

    while is_login:
        #print(is_login)
        print_main_menu()
        user_choice = input()
        if user_choice == '1':
            checkin(session_token)
        elif user_choice == '2':
            checkout(session_token)
        elif user_choice == '3':
            grant(session_token)
        elif user_choice == '4':
            delete(session_token)
        elif user_choice == '5':
            logout(session_token)
            exit()
        else:
            print('not a valid choice')

clientID = ""
if __name__ == '__main__':
    # try to recognize the client ID
    project_home = "/home/cs6238/Desktop/Project4"
    cwd = os.getcwd()
    clientID = cwd.split("/")[-1]
    print(f"You are at {clientID}")
    node_certificate = f"{project_home}/{clientID}/certs/{clientID}.crt"
    node_key = f"{project_home}/{clientID}/certs/{clientID}.key"
    main()
