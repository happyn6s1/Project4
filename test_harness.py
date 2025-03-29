import subprocess
import os
import time
import json

# TODO: Configure gt_username
GT_USERNAME = "hjiang365"

print(f"The value of GT_USERNAME is: {GT_USERNAME}")

USER_1 = "user1"
USER_2 = "user2"

# Can change if you want.  Don't really need to.
# TODO: Change this to a file with 'a' if you want to log the outputs.
FNULL = open(os.devnull, "w")

DOCUMENT_NAME = "file1.txt"
DOCUMENT_TEXT = """This is a test.
This file is conducting a test of the 3S System.
This is only a test."""

BAD_DOCUMENT = "bad_document"


def login(proc, username, user_key):
    proc.stdin.write(username + "\n")
    proc.stdin.write(user_key + "\n")


def checkin(proc, document_name, security_flag):
    proc.stdin.write("1\n")
    proc.stdin.write(document_name + "\n")
    proc.stdin.write(security_flag + "\n")


def checkout(proc, document_name):
    proc.stdin.write("2\n")
    proc.stdin.write(document_name + "\n")


def grant(proc, document_name, target_user, access_right, time_duration):
    proc.stdin.write("3\n")
    proc.stdin.write(document_name + "\n")
    proc.stdin.write(target_user + "\n")
    proc.stdin.write(access_right + "\n")
    proc.stdin.write(time_duration + "\n")


def delete(proc, document_name):
    proc.stdin.write("4\n")
    proc.stdin.write(document_name + "\n")


def logout(proc):
    proc.communicate("5\n")


# Updated to allow multiple clients, test description, expected status code
# Removed exception checks. We want to know what errors occurred.


def check_testresult(client, test, expected_status=200):
    # This functions checks the result inside the gt_username file in the client folder
    #
    # client: 1 or 2 for client 1 or client2
    # test: string description of the test, only used in the display of the result
    # expected_status: 200 when successful then others like 700 or 702 when it should expect failure.
    #
    # Sleep for 1 second to allow the log to be written before checking.
    # TODO: Increase this sleep if your tests seems to fail with EOF errors.
    time.sleep(3)
    try:
        # Open the gt_username file and load the status
        with open("./client%s/%s" % (str(client), GT_USERNAME), "r") as file_:
            result = json.loads(file_.read())
            while not "status" in result:
                time.sleep(1)
                with open("./client%s/%s" % (str(client), GT_USERNAME), "r") as f:
                    result = json.loads(file_.read())
            actual_status = result["status"]
        # Clear the contents of the gt_username file
        with open("./client%s/%s" % (str(client), GT_USERNAME), "w") as f:
            f.truncate(0)

        # Add some coloring and results on fail.
        start = "\033[92m" if expected_status == actual_status else "\033[91m"
        # (-) denotes a negative test
        end = "" if expected_status == 200 else "(-)"
        # If test failed, output status codes for debugging.
        end += "" if expected_status == actual_status else " --- E=%d A=%d" % (
            expected_status, actual_status)
        end += "\033[0m"
        print(("%s[%s] %s" % (start, test, end)))
    except Exception as e:
        print("\033[91m" + str(e))


def check_file(file_path, should_exist=True):
    # Check if the file exists based on the value of should_exist.
    if should_exist:
        file_exists = os.path.exists(file_path)
    else:
        file_exists = not os.path.exists(file_path)

    # Set the color of the output based on whether the file exists or not.
    if file_exists:
        color = "\033[92m"  # green
    else:
        color = "\033[91m"  # red

    # Set the text to display based on whether the file exists or not.
    if should_exist:
        text = "found"
    else:
        text = "not found"

    # Reset the color and print the output.
    reset = "\033[0m"
    print(f"{color}[{file_path}] {text}{reset}")


def compare_file(file_path, expected_text, should_pass=True):
    # Add some coloring and results on fail.
    with open(file_path, "rb") as file_:
        actual_text = file_.read()
    start = "\033[92m" if (
                                  actual_text == bytes(expected_text, 'utf-8')) == should_pass else "\033[91m"
    end = "matches text" if should_pass else "not matches text"
    end += "\033[0m"

    print(("%s[%s] %s" % (start, file_path, end)))


def remove_file(file_path):
    if os.path.exists(file_path):
        os.remove(file_path)


def add_file(file_path, text):
    with open(file_path, "w") as file_:
        file_.write(text)


def start_client(client_name):
    client_directory = "./" + client_name
    add_file("%s/documents/checkin/%s" %
             (client_directory, DOCUMENT_NAME), DOCUMENT_TEXT)

    client = subprocess.Popen(
        ["python3", "client.py"],
        cwd=client_directory,
        stdin=subprocess.PIPE,
        stdout=FNULL,
        stderr=FNULL,
        bufsize=1,
        universal_newlines=True
    )
    return client


def main():
    # Start the server
    server = subprocess.Popen(
        ["./start_server.sh"],
        cwd="./server/application",
        stdout=FNULL,
        stderr=FNULL,
    )
    time.sleep(3)
    try:
        # files on client to look for after tests
        client1_checkin = "./client1/documents/checkin/%s" % DOCUMENT_NAME
        client2_checkin = "./client2/documents/checkin/%s" % DOCUMENT_NAME
        client1_checkout = "./client1/documents/checkout/%s" % DOCUMENT_NAME
        client2_checkout = "./client2/documents/checkout/%s" % DOCUMENT_NAME

        # file on server to look for after tests
        server_file = "./server/application/documents/%s" % DOCUMENT_NAME

        # file that doesn't exist on client or server
        bad_file = "./client1/documents/checkout/%s" % BAD_DOCUMENT

        ############# LOGIN START TESTING #############
        print("Login USER1 from client 1 with USER1 key test")
        client1 = start_client("client1")
        login(client1, USER_1, USER_1 + ".key")
        check_testresult(1, "login %s" % USER_1)

        print("Login USER1 from client 2 with USER2 key test")
        client2 = start_client("client2")
        login(client2, USER_1, USER_2 + ".key")
        check_testresult(2, "login %s with %s.key" % (USER_1, USER_2), 700)

        print("Login USER2 from client 2 with USER2 key test")
        client2 = start_client("client2")
        login(client2, USER_2, USER_2 + ".key")
        check_testresult(2, "login %s" % USER_2)
        ############# LOGIN END TESTING #############

        # Integrity
        print("Integrity")
        remove_file(server_file)
        # checkin with Integrity
        checkin(client1, DOCUMENT_NAME, "2")
        check_testresult(1, USER_1 + " Testing checkin User1 from Client1 with Integrity")
        check_file(server_file)
        compare_file(server_file, DOCUMENT_TEXT)
        remove_file(client1_checkout)
        checkout(client1, DOCUMENT_NAME)
        check_testresult(1, USER_1 + " checkout Integrity")
        check_file(client1_checkout)

        print("Messing with server side file")
        with open("./server/application/documents/" + DOCUMENT_NAME, "a") as file_:
            file_.write("/nNOT!")

        remove_file(client1_checkout)
        checkout(client1, DOCUMENT_NAME)
        check_testresult(1, USER_1 + " checkout Integrity", 703)
        check_file(client1_checkout, False)

        # Confidentiality
        print("Confidentiality")
        remove_file(server_file)
        checkin(client1, DOCUMENT_NAME, "1")
        check_testresult(1, USER_1 + " checkin Confidentiality")
        check_file(server_file)
        compare_file(server_file, DOCUMENT_TEXT, False)

        remove_file(client1_checkout)
        checkout(client1, DOCUMENT_NAME)
        check_testresult(1, USER_1 + " checkout Confidentiality")
        check_file(client1_checkout)

        # Missing file
        print("No file on server")
        remove_file(bad_file)
        checkout(client1, BAD_DOCUMENT)
        check_testresult(1, USER_1 + " checkout bad_document", 704)
        check_file(bad_file, False)

        # USER_2 checkin, checkout tests. All should fail.
        print((USER_2 + " can't access files"))
        checkin(client2, DOCUMENT_NAME, "1")
        check_testresult(2, USER_2 + " checkin Confidentiality", 702)
        checkin(client2, DOCUMENT_NAME, "2")
        check_testresult(2, USER_2 + " checkin Integrity", 702)

        remove_file(client2_checkout)
        checkout(client2, DOCUMENT_NAME)
        check_testresult(2, USER_2 + " checkout", 702)
        check_file(client2_checkout, False)

        # Grant
        print((USER_1 + " grant to all"))
        target_user = "0"
        access_right = "3"
        time_duration = "660"
        grant(client1, DOCUMENT_NAME, target_user, access_right, time_duration)
        check_testresult(1, USER_1 + " grant to all")

        checkin(client2, DOCUMENT_NAME, "1")
        check_testresult(2, USER_2 + " checkin")

        remove_file(client2_checkout)
        checkout(client2, DOCUMENT_NAME)
        check_testresult(2, USER_2 + " checkout")
        check_file(client2_checkout)

        # USER_2 specific grant by USER_1
        print((USER_1 + " grant to " + USER_2))
        target_user = USER_2
        access_right = "2"
        time_duration = "660"
        grant(client1, DOCUMENT_NAME, target_user, access_right, time_duration)
        check_testresult(1, USER_1 + " grant checkout to %s" % USER_2)

        checkin(client2, DOCUMENT_NAME, "1")
        check_testresult(2, USER_2 + " checkin", 702)

        remove_file(client2_checkout)
        checkout(client2, DOCUMENT_NAME)
        check_testresult(2, USER_2 + " checkout")
        check_file(client2_checkout)

        target_user = USER_2
        access_right = "1"
        time_duration = "660"
        grant(client1, DOCUMENT_NAME, target_user, access_right, time_duration)
        check_testresult(1, USER_1 + " grant checkin to " + USER_2)
        # problem area fix
        checkin(client2, DOCUMENT_NAME, "1")
        check_testresult(2, USER_2 + " checkin")

        remove_file(client2_checkout)
        checkout(client2, DOCUMENT_NAME)
        check_testresult(2, USER_2 + " checkout", 702)
        check_file(client2_checkout, False)

        # Grant expires
        print((USER_1 + " grant to all with 0 seconds"))
        target_user = "0"
        access_right = "3"
        time_duration = "0"
        grant(client1, DOCUMENT_NAME, target_user, access_right, time_duration)
        check_testresult(1, USER_1 + " grant to all")

        checkin(client2, DOCUMENT_NAME, "1")
        check_testresult(2, USER_2 + " checkin expired", 702)

        remove_file(client2_checkout)
        checkout(client2, DOCUMENT_NAME)
        check_testresult(2, USER_2 + " checkout expired", 702)
        check_file(client2_checkout, False)

        # USER_2 grant (fail)
        print((USER_2 + " tries to grant"))
        target_user = USER_1
        access_right = "3"
        time_duration = "660"
        grant(client2, DOCUMENT_NAME, target_user, access_right, time_duration)
        check_testresult(2, USER_2 + " grant to " + USER_1, 702)
        grant(client2, BAD_DOCUMENT, target_user, access_right, time_duration)
        check_testresult(2, USER_2 + " grant bad_document", 700)

        # Delete
        print("Delete tests")
        delete(client2, DOCUMENT_NAME)
        check_testresult(2, USER_2 + " delete", 702)
        check_file(server_file)

        delete(client1, DOCUMENT_NAME)
        check_testresult(1, USER_1 + " delete")
        check_file(server_file, False)

        delete(client2, DOCUMENT_NAME)
        check_testresult(2, USER_2 + " delete", 704)

        # Logout
        print("Logout tests")
        remove_file(server_file)
        check_file(server_file, False)

        logout(client1)
        check_testresult(1, USER_1 + " logout")
        check_file(server_file, False)

        logout(client2)
        check_testresult(2, USER_2 + " logout")

    except Exception as e:
        print(e)
    finally:
        # Cleanup
        server.terminate()

        remove_file(client1_checkin)
        remove_file(client1_checkout)
        remove_file(client2_checkin)
        remove_file(client2_checkout)
        remove_file(server_file)

        # TODO: Write your own metafile/database cleanup on server
        remove_file("./server/application/documents/." + DOCUMENT_NAME)


if __name__ == "__main__":
    main()
