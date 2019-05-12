from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP


server_keys = RSA.generate(2048)

# file_out = open("/Users/nihalpai/Desktop/SFTA/server_keys.pem", "wb")
# file_out.write(server_keys)
# file_out.close()

file_out = open("/Users/nihalpai/Desktop/SFTA/server_pub_key.pem", "wb")
file_out.write(server_keys.publickey().export_key())
file_out.close()

file_out = open("/Users/nihalpai/Desktop/SFTA/server_priv_key.pem", "wb")
file_out.write(server_keys.export_key())
file_out.close()



client_keys = RSA.generate(2018)

# file_out = open("/Users/nihalpai/Desktop/SFTA/client_keys.pem", "wb")
# file_out.write(client_keys)
# file_out.close()

file_out = open("/Users/nihalpai/Desktop/SFTA/client_pub_key.pem", "wb")
file_out.write(client_keys.publickey().export_key())
file_out.close()

file_out = open("/Users/nihalpai/Desktop/SFTA/client_priv_key.pem", "wb")
file_out.write(client_keys.export_key())
file_out.close()
exit()