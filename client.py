import requests


#path('/', views.api_index, name='api_index'),
def index():
    r = requests.get("http://localhost:8000/")
    print(r.text)
    return


#path('signup/', views.api_signup, name='api_signup'),
def signup():
    pass


#path('signin/', views.api_signin, name='api_signin'),
def signin():
    pass


#path('my_files/', views.api_my_files, name='api_my_files'),
def my_files():
    pass


#path('my_access/', views.api_my_access, name='api_my_access'),
def my_access():
    pass


#path('upload/', views.api_upload, name='api_upload'),
def upload():
    pass


#path('download/', views.api_download, name='api_download'),
def download():
    pass


#path('share/', views.api_share, name='api_share'),
def share():
    pass


#path('revoke/', views.api_revoke, name='api_revoke'),
def revoke():
    pass


def client():
    print("Welcome! Usage:\n \t'quit' to exit\n\t'path' to request that path. Parameters determined interactively")
    command = ""
    authenticated = False
    while (command != "quit"):
        print("Enter relative url")
        command = input().lower()
        if command == "":
            index()
        elif command == "signup":
            signup()
        elif command == "signin":
            signin()
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
            return
        else:
            print("command not recognized")
        print("Request complete")


if __name__ == "__main__":
    client()
