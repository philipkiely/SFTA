import requests
import ast
import os.path
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto import Random


def save_state():
    global state
    print(state)
    with open("state.txt", "w") as f:
        f.write(str(state))
    

def load_state():
    try:
        with open("state.txt", "r") as f:
            return ast.literal_eval(f.read()) # state
    except:
        return {"authenticated": False, "token": "", "client_msn": 0, "server_msn": 0} # initial state


def check_server_msn(msn):
    global state
    if state["server_msn"] >= msn:
        print("message sequence number too low, possible replay")
        return False
    state["server_msn"] = msn
    save_state()
    return True


#path('/', views.api_index, name='api_index'),
def index():
    global state
    r = requests.get("http://localhost:8000/")
    print(r.text)
    return


#path('signup/', views.api_signup, name='api_signup'),
def signup():
    global state
    print("Enter a username")
    username = input()
    print("Enter a password")
    password = input()
    print("Enter an email")
    email = input()
    data = {"username": username, "password": password, "email": email}

    ##################################################################################################################
    # Encrypt Request data to send to server

    # Load Server's Public Key
    file_in = open("/Users/nihalpai/Desktop/SFTA/server_pub_key.pem", "r")
    server_key = RSA.import_key(file_in.read())
    file_in.close()

    # Encrypt Data with Server's Public Key
    request_dict = (str(data)).encode("utf-8")
    server_cipher = PKCS1_OAEP.new(server_key)
    encrypted_request_dict = server_cipher.encrypt(request_dict)
    encrypted_request_data = {"data": encrypted_request_dict}
    print("\nEncrypted Request Data CLIENT SIDE: ", encrypted_request_data)
    ##################################################################################################################

    r = requests.post("http://localhost:8000/signup/", data=encrypted_request_data).json()

    ##################################################################################################################
    # Decrypt the Response from server

    # Load Client's Private Key
    file_in = open("/Users/nihalpai/Desktop/SFTA/client_priv_key.pem", "r")
    client_priv_key = RSA.import_key(file_in.read())
    file_in.close()

    client_cipher = PKCS1_OAEP.new(client_priv_key)
    print("\nEncrypted Response CLIENT SIDE: ", r)
    decrypted_r = server_cipher.decrypt(r)
    print("\nDecrypted Request Data CLIENT SIDE: ", decrypted_r) # Is this in proper format?
    ##################################################################################################################

    if decrypted_r["authenticated"]:
        state["authenticated"] = True
        state["token"] = decrypted_r["token"]
    print(state)
    return


#path('signin/', views.api_signin, name='api_signin'),
def signin():
    global state
    print("Enter your username")
    username = input()
    print("Enter your password")
    password = input()
    data = {"username": username, "password": password}

    r = requests.post("http://localhost:8000/signin/", data=data).json()
    if r["authenticated"]:
        state["authenticated"] = True
        state["token"] = r["token"]
    else:
        print("Invalid Credentials")
        signin()
    return




#path('my_files/', views.api_my_files, name='api_my_files'),
def my_files():
    global state
    state["client_msn"] = state["client_msn"] + 1
    data = {"client_msn": state["client_msn"]}
    headers = {"Authorization": state["token"]}
    r = requests.post("http://localhost:8000/my_files/", headers=headers, data=data).json()
    if not check_server_msn(int(r["server_msn"])):
        return
    print(r)


#path('my_access/', views.api_my_access, name='api_my_access'),
def my_access():
    global state
    state["client_msn"] = state["client_msn"] + 1
    data = {"client_msn": state["client_msn"]}
    if not check_server_msn(int(r["server_msn"])):
        return


#path('upload/', views.api_upload, name='api_upload'),
def upload():
    global state
    state["client_msn"] = state["client_msn"] + 1
    data = {"client_msn": state["client_msn"]}
    if not check_server_msn(int(r["server_msn"])):
        return


#path('download/', views.api_download, name='api_download'),
def download():
    global state
    state["client_msn"] = state["client_msn"] + 1
    data = {"client_msn": state["client_msn"]}
    if not check_server_msn(int(r["server_msn"])):
        return


#path('share/', views.api_share, name='api_share'),
def share():
    global state
    state["client_msn"] = state["client_msn"] + 1
    data = {"client_msn": state["client_msn"]}
    if not check_server_msn(int(r["server_msn"])):
        return


#path('revoke/', views.api_revoke, name='api_revoke'),
def revoke():
    global state
    state["client_msn"] = state["client_msn"] + 1
    data = {"client_msn": state["client_msn"]}
    if not check_server_msn(int(r["server_msn"])):
        return


def client():
    print("Welcome! Usage:\n \t'quit' to exit\n\t'path' to request that path. Parameters determined interactively")
    command = ""
    while (command != "quit"):
        print("Enter relative url")
        command = input().lower()
        if command == "":
            index()
        elif command == "signup":
            signup()
            print("authenticated")
        elif command == "signin":
            signin()
            print("authenticated")
        elif command == "my_files":
            my_files()
        elif command == "my_access":
            my_access()
        elif command == "upload":
            upload()
        elif command == "download":
            download()
        elif command == "share":
            share()
        elif command == "revoke":
            revoke()
        elif command == "quit":
            save_state()
            return
        else:
            print("command not recognized")
        save_state()
        print("Request complete")


if __name__ == "__main__":
    state = load_state()
    client()
