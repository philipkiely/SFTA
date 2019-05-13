import requests
import ast
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util import Padding
from Crypto import Random


def encrypt_request_data(request_data):
    # Load Server's Public Key
    file_in = open("server_pub_key.pem", "r")
    server_key = RSA.import_key(file_in.read())
    file_in.close()

    # Encrypt Data with Server's Public Key
    request_dict = (str(request_data)).encode("utf-8")
    server_cipher = PKCS1_OAEP.new(server_key)
    encrypted_request_dict = str(list(server_cipher.encrypt(request_dict)))
    return {"data": encrypted_request_dict}


def decrypt_response_data(response_data):
    # Load Client's Private Key
    file_in = open("client_priv_key.pem", "r")
    client_priv_key = RSA.import_key(file_in.read())
    file_in.close()

    # Decrypt Response data from Server
    client_cipher = PKCS1_OAEP.new(client_priv_key)
    return ast.literal_eval(str(client_cipher.decrypt(bytes(ast.literal_eval(response_data))))[2:-1])


def save_state():
    global state
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

    encrypted_request_data = encrypt_request_data(data)

    r = requests.post("http://localhost:8000/signup/", data=encrypted_request_data).json()

    decrypted_r = decrypt_response_data(r['response'])

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

    encrypted_request_data = encrypt_request_data(data)

    r = requests.post("http://localhost:8000/signin/", data=encrypted_request_data).json()

    decrypted_r = decrypt_response_data(r['response'])

    if decrypted_r["authenticated"]:
        state["authenticated"] = True
        state["token"] = decrypted_r["token"]
    else:
        print("Invalid Credentials")
        signin()
    return


#path('my_files/', views.api_my_files, name='api_my_files'),
def my_files(): ####
    global state
    state["client_msn"] = state["client_msn"] + 1
    data = {"client_msn": state["client_msn"]}
    headers = {"Authorization": state["token"]}

    encrypted_headers = encrypt_request_data(headers)
    encrypted_data   = encrypt_request_data(data)
    # print(encrypted_header, "\n", encrypted_data)

    r = requests.post("http://localhost:8000/my_files/", headers=headers, data=encrypted_data).json()

    decrypted_r = decrypt_response_data(r['response'])

    if not check_server_msn(int(decrypted_r["server_msn"])):
        return
    print(decrypted_r)


#path('my_access/', views.api_my_access, name='api_my_access'),
def my_access(): #####
    global state
    state["client_msn"] = state["client_msn"] + 1
    data = {"client_msn": state["client_msn"]}
    headers = {"Authorization": state["token"]}

    encrypted_data = encrypt_request_data(data)

    r = requests.post("http://localhost:8000/my_access/", headers=headers, data=encrypted_data).json()

    decrypted_r = decrypt_response_data(r['response'])

    if not check_server_msn(int(decrypted_r["server_msn"])):
        return
    print(decrypted_r)


#path('upload/', views.api_upload, name='api_upload'),
def upload(): #####
    global state
    state["client_msn"] = state["client_msn"] + 1
    data = {"client_msn": state["client_msn"]}

    encrypted_data = encrypt_request_data(data)

    print("path to file you want to upload")
    path = input()
    ifile = open(path, 'rb')
    plaintext = ifile.read()
    ifile.close()
    #MODIFIED FROM HW3 QUESTION 1 / HW3 QUESTION 1 SOLUTIONS
    # apply PKCS7 padding on the plaintext
    padded_plaintext = Padding.pad(plaintext, AES.block_size)
    # generate random IV and create an AES-CBC cipher object
    iv = Random.get_random_bytes(AES.block_size)
    key = "SHAREDSECRET4444".encode('utf-8')
    cipher_CBC = AES.new(key, AES.MODE_CBC, iv)
    # also create an AES-ECB object for encrypting the IV
    cipher_ECB = AES.new(key, AES.MODE_ECB)
    # write out the encrypted IV and the padded and encrypted plaintext to the output file
    ofile = open("tempencrypted/" + path, "wb+")
    ofile.write(cipher_ECB.encrypt(iv))
    ofile.write(cipher_CBC.encrypt(padded_plaintext))
    ofile.close()
    files = {'file': open("tempencrypted/" + path, 'rb')}
    headers = {"Authorization": state["token"]}

    r = requests.post("http://localhost:8000/upload/", headers=headers, data=encrypted_data, files=files).json()

    decrypted_r = decrypt_response_data(r['response'])

    os.remove("tempencrypted/" + path)
    if not check_server_msn(int(decrypted_r["server_msn"])):
        return
    print(decrypted_r)


#path('download/', views.api_download, name='api_download'),
def download():
    global state
    state["client_msn"] = state["client_msn"] + 1
    print("ID of file you want to download")
    fileID = int(input())
    data = {"client_msn": state["client_msn"], "fileID": fileID}
    headers = {"Authorization": state["token"]}
    r = requests.post("http://localhost:8000/download/", headers=headers, data=data, stream=True)
    #if not check_server_msn(int(r["server_msn"])):
    #    return
    print("Save As:")
    save_path = input()
    with open("tempencrypted/" + save_path, "wb+") as f:
        for chunk in r.iter_content(1024):
            f.write(chunk)
    #MODIFIED FROM HW3 QUESTION 1 / HW3 QUESTION 1 SOLUTIONS
    ifile = open("tempencrypted/" + save_path, 'rb')
    encrypted_iv = ifile.read(AES.block_size)
    ciphertext = ifile.read()
    ifile.close()
    # create 2 AES cipher objects, one for decrypting the IV and one for decrypting the payload
    # and initialize these cipher objects with the appropriate parameters
    key = "SHAREDSECRET4444".encode('utf-8')
    cipher_ECB = AES.new(key, AES.MODE_ECB)
    iv = cipher_ECB.decrypt(encrypted_iv)
    cipher_CBC = AES.new(key, AES.MODE_CBC, iv)
    # decrypt the ciphertext and remove padding
    padded_plaintext = cipher_CBC.decrypt(ciphertext)
    plaintext = Padding.unpad(padded_plaintext, AES.block_size)
    # write out the plaintext into the output file
    ofile = open(save_path, "wb+")
    ofile.write(plaintext)
    ofile.close()
    os.remove("tempencrypted/" + save_path)
    return


#path('share/', views.api_share, name='api_share'),
def share(): ####
    global state
    state["client_msn"] = state["client_msn"] + 1
    headers = {"Authorization": state["token"]}
    print("FileID that you want to share")
    fileID = int(input())
    print("Email of user to share with")
    email = input()
    data = {"client_msn": state["client_msn"], "fileID": fileID, "email": email}

    encrypted_data = encrypt_request_data(data)

    r = requests.post("http://localhost:8000/share/", headers=headers, data=encrypted_data).json()

    decrypted_r = decrypt_response_data(r['response'])

    if not check_server_msn(int(decrypted_r["server_msn"])):
        return
    print(decrypted_r)


#path('revoke/', views.api_revoke, name='api_revoke'),
def revoke(): #####
    global state
    state["client_msn"] = state["client_msn"] + 1
    headers = {"Authorization": state["token"]}
    print("FileID that you want to revoke")
    fileID = int(input())
    print("Email of user to revoke from")
    email = input()
    data = {"client_msn": state["client_msn"], "fileID": fileID, "email": email}

    encrypted_data = encrypt_request_data(data)

    r = requests.post("http://localhost:8000/revoke/", headers=headers, data=encrypted_data).json()

    decrypted_r = decrypt_response_data(r['response'])

    if not check_server_msn(int(decrypted_r["server_msn"])):
        return
    print(decrypted_r)


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
    os.makedirs("tempencrypted", exist_ok=True)
    client()
