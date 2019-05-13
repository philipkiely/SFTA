# SFTA

Secure File Transfer Application

By Philip Kiely and Nihal Pai

## Running SFTA

Note: this project requires Python 3\. All uses of the terminal commands `python` and `pip` refer to Python 3.

Before proceeding, create a Python virtual environment for this project and, in the "SFTA" directory, run `pip install -r requirements.txt`

To generate RSA keys, run `python key_gen.py`. This creates keypairs for the the server. We assume that the client can access the server's public key and that the server can access the client's public key, and we model that access locally by having them read from each others' public key files directly. For the purposes of testing, signing up a new user creates a new state.txt and public and private key for the system, then shares the public key of that new client with the server out of band.

### Server

Create a Django Secret Key the same way that Django does it during `startproject` (used internally, not by our crypto code):

```
import random
''.join(random.SystemRandom().choice('abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)') for i in range(50))
```

Set the following environment variables:

```
export SFTA_SECRET_KEY="" #the key you just generated
export SFTA_DEBUG_INT="1"
export SFTA_DB_NAME="sftaDB" #Change this if it changes in next step
export SFTA_DB_USER="postgres" #Change this if it changes in next step
export SFTA_DB_PASS="postgres" #Change this if it changes in next step
export SFTA_DB_HOST="127.0.0.1"
export SFTA_DB_PORT=""
```

Install [PostgreSQL](https://www.postgresql.org/download/) and, if desired, a GUI like [pgAdmin](https://www.pgadmin.org/download/). Next, create a postgreSQL database. The name of the database should match the environment variable `SFTA_DB_NAME` and the username and password of a postgres user that can access the database should match the environment variables `SFTA_DB_USER` and `SFTA_DB_PASS`.

Finally, cd into "SFTA/encryptransfer" (the one with `manage.py` in it) and run:

- `python manage.py migrate` (migrations are made locally and pushed with code)
- `python manage.py runserver`

If you want to create a superuser, quit the server, run `python manage.py createsuperuser`, then run the server again.

To view the available endpoints, go to `http://127.0.0.1:8000`. If you want to see the administrator view, go to `/admin` on the same address and port and login with the superuser credentials you just set.

### Client

The hard part is over. In a new terminal window, navigate to "SFTA" and run `python client.py`. Follow the instructions in the terminal to send requests. You can examine the state at any time by opening `state_{username}.txt` in any text editor. Upon signup, the client will create and share the public part (out of band) of its keys to simulate the fact that on a real network, the user would be a different computer with different keys.

You'll want to start by signing up and uploading then downloading a file. Remember that you can pass username as a command line argument `python client.py username` to load a particular user's state.

### Note for production

SFTA has two components: a client (`client.py` and generated files) and a server (`encryptransfer` and all of its contents). It is a demo project designed to run locally. In production, you would only need the `encryptransfer` directory on your server. Then, you would change the urls in `client.py` to whatever url the server exposed. Despite the protections offered by our cryptographic protocols, you would want to configure the server to only run over HTTPS. Finally, while the application will handle files of up to Gigabyte size locally, various optimizations would need to be made to serve such files efficiently on a production server (notably configuring Apache).

Deploying a Django project into production is a nontrivial but achievable task. More information on how to properly configure settings (turning off DEBUG, hiding the server secret, etc) is outside the scope of this documentation.
