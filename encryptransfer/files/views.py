from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.authentication import SessionAuthentication, BasicAuthentication, TokenAuthentication
from rest_framework.reverse import reverse
from rest_framework.authtoken.models import Token
from rest_framework.status import HTTP_400_BAD_REQUEST
from ratelimit.decorators import ratelimit
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.conf import settings
from .decorators import define_usage
from .models import File, AccessController, Profile
import mimetypes

import os.path
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import ast



#TODO: MAC on responses
#TODO: Encrypt files

#path('/', views.api_index, name='api_index'),
@ratelimit(key='ip', rate='1/s')
@define_usage(returns={"url_usage": "Dict"})
@api_view(["GET"])
@permission_classes((AllowAny,))
def api_index(request):
    details = {}
    for item in list(globals().items()):
        if item[0][0:4] == "api_":
            if hasattr(item[1], "usage"):
                details[reverse(item[1].__name__)] = item[1].usage
    return Response(details)

#path('signup/', views.api_signup, name='api_signup'),
@ratelimit(key='ip', rate='1/s')
@define_usage(params={"email": "String", "username": "String", "password": "String"},
              returns={'authenticated': 'Bool', 'token': 'Token String'})
@api_view(["POST"])
@permission_classes((AllowAny,))
def api_signup(request):

    ############################################################################################################## 
    # Load Server's Private Key
    file_in = open("/Users/nihalpai/Desktop/SFTA/server_priv_key.pem", "r")
    server_priv_key = RSA.import_key(file_in.read())
    file_in.close()
 
    # Decrypt Request data from Client
    server_cipher = PKCS1_OAEP.new(server_priv_key)
    print("\nEncrypted Request Data SERVER SIDE: ", request.data)
    # print("\nDictionary value to decrypt i.e. request.data['data'] :", request.data['data'])
    decrypted_request_data = ast.literal_eval(server_cipher.decrypt(request.data['data']))
    print("\nDecrypted Request Data SERVER SIDE: ", decrypted_request_data) # should be {"email": ----, "username": ---, "password": ---} format
    ##############################################################################################################

    try:
        email = decrypted_request_data['email']
        username = decrypted_request_data['username']
        password = decrypted_request_data['password']
    except:
        return Response({'error': 'Please provide correct email, username, and password'},
                        status=HTTP_400_BAD_REQUEST)

    user = User.objects.create_user(username, email, password)
    user.save()
    user = authenticate(username=username, password=password)
    user_profile = Profile(user=user, server_msn=0, client_msn=0)
    user_profile.save()
    if user is not None:
        token, _ = Token.objects.get_or_create(user=user)
        response_dict = {'authenticated': True, 'token': "Token " + token.key}
    else:
        response_dict = {'authenticated': False, 'token': None}

    ##############################################################################################################
    # Read in Client's Public Key
    file_in = open("/Users/nihalpai/Desktop/SFTA/client_pub_key.pem", "wb")
    client_key = RSA.import_key(file_in.read())
    file_in.close()

    # Encrypt Response for Client
    client_cipher =  PKCS1_OAEP.new(client_key)
    encrypted_response_dict = server_cipher.encrypt(str(response_dict).encode("utf-8"))
    print("\nEncrypted Response SERVER SIDE: ", encrypted_response_dict)
    ##############################################################################################################

    return Response(encrypted_response_dict)


#path('signin/', views.api_signin, name='api_signin'),
@ratelimit(key='ip', rate='1/s')
@define_usage(params={"username": "String", "password": "String"},
              returns={'authenticated': 'Bool', 'token': 'Token String'})
@api_view(["POST"])
@permission_classes((AllowAny,))
def api_signin(request):
    try:
        username = request.data['username']
        password = request.data['password']
    except:
        return Response({'error': 'Please provide correct username and password'},
                        status=HTTP_400_BAD_REQUEST)
    user = authenticate(username=username, password=password)

    ##############################################################################################################    
    # Encrypting Signin request.data with RSA: dictionary -> string -> utf-8 encode  
    # Generate RSA Key
    key_signinreq = RSA.generate(2048)

    # Private Key
    priv_key_signinreq = key_signinreq.export_key()
    # print("REACHED:   ", priv_key_signinreq)
    file_out = open("/Users/nihalpai/Desktop/SFTA/private_signinreq.pem", "wb")
    file_out.write(priv_key_signinreq)
    file_out.close()

    # Public Key
    pub_key_signinreq = key_signinreq.publickey().export_key()
    file_out = open("/Users/nihalpai/Desktop/SFTA/receiver_signinreq.pem", "wb")
    file_out.write(pub_key_signinreq)
    file_out.close()

    # Encrypt Data
    signin_request_data = str({'username': username, 'password': password}).encode("utf-8")
    file_out = open("/Users/nihalpai/Desktop/SFTA/encrypted_signin_request_data.bin", "wb")

    # Generate Recipient & Session Keys
    recipient_key_signinreq = RSA.import_key(open("/Users/nihalpai/Desktop/SFTA/receiver_signinreq.pem").read())
    session_key_signinreq = get_random_bytes(16)

    # Encrypt session key with public RSA key
    cipher_rsa_signinreq = PKCS1_OAEP.new(recipient_key_signinreq)
    enc_session_key_signinreq = cipher_rsa_signinreq.encrypt(session_key_signinreq)

    # Encrypt request data with AES session key
    cipher_aes_signinreq = AES.new(session_key_signinreq, AES.MODE_EAX)
    ciphertext_signinreq, tag_signinreq = cipher_aes_signinreq.encrypt_and_digest(signin_request_data)
    [ file_out.write(x) for x in (enc_session_key_signinreq, cipher_aes_signinreq.nonce, tag_signinreq, ciphertext_signinreq) ]
    file_out.close()
    ##############################################################################################################

    if user is not None:
        token, _ = Token.objects.get_or_create(user=user)
        response = Response({'authenticated': True, 'token': "Token " + token.key})
    else:
        response = Response({'authenticated': False, 'token': None})

    ##############################################################################################################    
    # Encrypting Signin Response with RSA

    # Generate RSA Key
    key_signinresp = RSA.generate(2048)

    # Private Key
    priv_key_signinresp = key_signinresp.export_key()
    file_out = open("/Users/nihalpai/Desktop/SFTA/private_signinresp.pem", "wb")
    file_out.write(priv_key_signinresp)
    file_out.close()

    # Public Key
    pub_key_signinresp = key_signinresp.publickey().export_key()
    file_out = open("/Users/nihalpai/Desktop/SFTA/receiver_signinresp.pem", "wb")
    file_out.write(pub_key_signinresp)
    file_out.close()

    # Encrypt Data
    signinresp_data = str({'authenticated': True, 'token': "Token " + token.key}).encode("utf-8")
    file_out = open("/Users/nihalpai/Desktop/SFTA/encrypted_signin_response_data.bin", "wb")

    # Generate Recipient & Session Keys
    recipient_key_signinresp = RSA.import_key(open("/Users/nihalpai/Desktop/SFTA/receiver_signinresp.pem").read())
    session_key_signinresp = get_random_bytes(16)

    # Encrypt session key with public RSA key
    cipher_rsa_signinresp = PKCS1_OAEP.new(recipient_key_signinresp)
    enc_session_key_signinnresp = cipher_rsa_signinresp.encrypt(session_key_signinresp)

    # Encrypt true response data with AES session key
    cipher_aes_signinresp = AES.new(session_key_signinresp, AES.MODE_EAX)
    ciphertext_signinresp, tag_signinresp = cipher_aes_signinresp.encrypt_and_digest(signinresp_data)
    [ file_out.write(x) for x in (enc_session_key_signinresp, cipher_aes_signinresp.nonce, tag_signinresp, ciphertext_signinresp) ]
    file_out.close()
    ##############################################################################################################

    return response




#checking client msn
def check_client_msn(request):
    if int(request.data['client_msn']) <= request.user.profile.client_msn:
        return False
    request.user.profile.client_msn = int(request.data['client_msn'])
    request.user.profile.save()
    return True


#wrapper for Response, introduces sequence numbers #TODO encryption and mac
def protected_response(request, data):
    new_server_msn = request.user.profile.server_msn + 1
    data["server_msn"] = new_server_msn
    request.user.profile.server_msn = new_server_msn
    request.user.profile.save()
    return Response(data)


#path('my_files/', views.api_my_files, name='api_my_files'),
@ratelimit(key='ip', rate='1/s')
@define_usage(params={'client_msn': 'Integer'}, returns={'file_metadata': 'Dict'})
@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((IsAuthenticated,))
def api_my_files(request):
    if not check_client_msn(request):
        return protected_response(request, {'error': 'error'})
    file_list = dict(request.user.file_set.all())
    return protected_response(request, file_list)


#path('my_access/', views.api_my_access, name='api_my_access'),
@ratelimit(key='ip', rate='1/s')
@define_usage(params={'client_msn': 'Integer'}, returns={'file_metadata': 'Dict'})
@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((IsAuthenticated,))
def api_my_access(request):
    if not check_client_msn(request):
        return protected_response(request, {'error': 'error'})
    access_list = dict(request.user.accesscontroller_set.all())
    return protected_response(request, access_list)


#path('upload/', views.api_upload, name='api_upload'),
@ratelimit(key='ip', rate='1/s')
@define_usage(params={'file': 'File', 'client_msn': 'Integer'}, returns={'success': 'Boolean', 'fileID': 'String'})
@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((IsAuthenticated,))
def api_upload(request):
    if not check_client_msn(request):
        return protected_response(request, {'error': 'error'})
    new_file = File(owner=request.user, file=request.FILES.get('file'))
    new_file.save()
    return protected_response(request, {'success': 'True', 'fileID': new_file.id})


#path('download/', views.api_download, name='api_download'),
@ratelimit(key='ip', rate='1/s')
@define_usage(params={'fileID': 'Int', 'client_msn': 'Integer'}, returns={'file': 'File'})
@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((IsAuthenticated,))
def api_download(request):
    if not check_client_msn(request):
        return protected_response(request, {'error': 'error'})
    f = File.objects.get(id=request.data['fileID'])
    if f.owner == request.user:
        data = f.file.read() #in production this would instead be handled by Apache
        f.file.close()
        response = HttpResponse(data, content_type=mimetypes.guess_type(settings.MEDIA_ROOT + f.file.name)[0])
        response['Content-Disposition'] = "attachment; filename={0}".format(f.file)
        response['Content-Length'] = f.file.size
        return response
        #return protected_response(request, {'success': 'True', 'fileID': f.id})
    else:
        try:
            ac = AccessController.objects.get(user=request.user, file=f)
            data = ac.file.file.read() #in production this would instead be handled by Apache
            ac.file.file.close()
            response = Response(data, content_type=mimetypes.guess_type(settings.MEDIA_ROOT + ac.file.file.name)[0])
            response['Content-Disposition'] = "attachment; filename={0}".format(ac.file.file)
            response['Content-Length'] = ac.file.file.size
            return response
        except:
            return protected_response(request, {'success': 'False', 'fileID': 'You cannot access this file'})


#path('share/', views.api_share, name='api_share'),
@ratelimit(key='ip', rate='1/s')
@define_usage(params={'file_id': 'Int', 'file_key': 'String', 'email': 'String', 'client_msn': 'Integer'}, returns={'success': 'Boolean'})
@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((IsAuthenticated,))
def api_share(request):
    if not check_client_msn(request):
        return protected_response(request, {'error': 'error'})
    f = File.objects.get(id=request.data['fileID'])
    if f.owner == request.user:
        ac = AccessController(user=User.objects.get(email=request.data["email"]), file=f)
        ac.save()
    return protected_response(request, {'success': 'True'})


#path('revoke/', views.api_revoke, name='api_revoke'),
@ratelimit(key='ip', rate='1/s')
@define_usage(params={'file_id': 'Int', 'email': 'String', 'client_msn': 'Integer'}, returns={'success': 'Boolean'})
@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((IsAuthenticated,))
def api_revoke(request):
    if not check_client_msn(request):
        return protected_response(request, {'error': 'error'})
    f = File.objects.get(id=request.data['fileID'])
    if f.owner == request.user:
        ac = AccessController.objects.get(user=User.objects.get(email=request.data["email"]), file=f)
        ac.delete()
    return protected_response(request, {'success': 'True'})
