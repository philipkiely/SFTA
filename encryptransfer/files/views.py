from rest_framework.permissions import AllowAny
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
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import ast


def decrypt_request_data(request_data):
    # Read in Server's Private Key
    file_in = open(settings.MEDIA_ROOT + "server_priv_key.pem", "r")
    server_priv_key = RSA.import_key(file_in.read())
    file_in.close()
    # Decrypt Request data from Client
    server_cipher = PKCS1_OAEP.new(server_priv_key)
    return ast.literal_eval(str(server_cipher.decrypt(bytes(ast.literal_eval(request_data))))[2:-1])


def encrypt_response_data(response_dict, username):
    # Read in Client's Public Key
    file_in = open(settings.MEDIA_ROOT + "client_pub_key_{}.pem".format(username), "r")
    client_key = RSA.import_key(file_in.read())
    file_in.close()

    # Encrypt Response for Client
    response_dict = (str(response_dict)).encode("utf-8")
    client_cipher = PKCS1_OAEP.new(client_key)
    return str(list(client_cipher.encrypt(response_dict)))


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
@define_usage(params={"username": "String", "password": "String"},
              returns={'authenticated': 'Bool', 'token': 'Token String'})
@api_view(["POST"])
@permission_classes((AllowAny,))
def api_signup(request):

    decrypted_request_data = decrypt_request_data(request.data['data'])

    try:
        username = decrypted_request_data['username']
        password = decrypted_request_data['password']
        email = username + "@fakemail.com" #basically Django requires email but we're ignoring it
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

    encrypted_response_dict = encrypt_response_data(response_dict, user.username)

    return Response({'response': encrypted_response_dict})


#path('signin/', views.api_signin, name='api_signin'),
@ratelimit(key='ip', rate='1/s')
@define_usage(params={"username": "String", "password": "String"},
              returns={'authenticated': 'Bool', 'token': 'Token String'})
@api_view(["POST"])
@permission_classes((AllowAny,))
def api_signin(request):

    decrypted_request_data = decrypt_request_data(request.data['data'])

    try:
        username = decrypted_request_data['username']
        password = decrypted_request_data['password']
    except:
        return Response({'error': 'Please provide correct username and password'},
                        status=HTTP_400_BAD_REQUEST)
    user = authenticate(username=username, password=password)

    if user is not None:
        token, _ = Token.objects.get_or_create(user=user)
        response_dict = {'authenticated': True, 'token': "Token " + token.key}
    else:
        response_dict = {'authenticated': False, 'token': None}

    encrypted_response_dict = encrypt_response_data(response_dict, user.username)

    return Response({'response': encrypted_response_dict})


#checking client msn
def check_client_msn(user, decrypted_request_data): #### decrypt requests before calling this, change input to this to the encrypted version
    if int(decrypted_request_data['client_msn']) <= user.profile.client_msn:
        return False
    user.profile.client_msn = int(decrypted_request_data['client_msn'])
    user.profile.save()
    return True


#wrapper for Response, introduces sequence numbers #TODO encryption and mac
def protected_response(user, data):
    new_server_msn = user.profile.server_msn + 1
    data["server_msn"] = new_server_msn
    user.profile.server_msn = new_server_msn
    user.profile.save()
    # Encrypt data
    # return Response(data)
    return Response({'response': encrypt_response_data(data, user.username)})


def custom_auth(data):
    return Token.objects.get(key=decrypt_request_data(data)['Authorization'][6:]).user


#path('my_files/', views.api_my_files, name='api_my_files'),
@ratelimit(key='ip', rate='1/s')
@define_usage(params={'client_msn': 'Integer'}, returns={'file_metadata': 'Dict'})
@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((AllowAny,))
def api_my_files(request):
    user = custom_auth(request.headers["data"])
    decrypted_request_data = decrypt_request_data(request.data['data'])
    if not check_client_msn(user, decrypted_request_data):
        return protected_response(user, {'error': 'error'})
    file_list = {"files": list(user.file_set.values())}
    return protected_response(user, file_list)


#path('my_access/', views.api_my_access, name='api_my_access'),
@ratelimit(key='ip', rate='1/s')
@define_usage(params={'client_msn': 'Integer'}, returns={'file_metadata': 'Dict'})
@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((AllowAny,))
def api_my_access(request):
    user = custom_auth(request.headers["data"])
    decrypted_request_data = decrypt_request_data(request.data['data'])
    if not check_client_msn(user, decrypted_request_data):
        return protected_response(user, {'error': 'error'})
    access_list = {"access": list(user.accesscontroller_set.values())}
    return protected_response(user, access_list)


#path('upload/', views.api_upload, name='api_upload'),
@ratelimit(key='ip', rate='1/s')
@define_usage(params={'file': 'File', 'client_msn': 'Integer'}, returns={'success': 'Boolean', 'fileID': 'String'})
@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((AllowAny,))
def api_upload(request):
    user = custom_auth(request.headers["data"])
    decrypted_request_data = decrypt_request_data(request.data['data'])
    if not check_client_msn(user, decrypted_request_data):
        return protected_response(user, {'error': 'error'})
    new_file = File(owner=user, file=request.FILES.get('file'))
    new_file.save()
    return protected_response(user, {'success': 'True', 'fileID': new_file.id})


#path('download/', views.api_download, name='api_download'),
@ratelimit(key='ip', rate='1/s')
@define_usage(params={'fileID': 'Int', 'client_msn': 'Integer'}, returns={'file': 'File'})
@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((AllowAny,))
def api_download(request):
    user = custom_auth(request.headers["data"])
    decrypted_request_data = decrypt_request_data(request.data['data'])
    if not check_client_msn(user, decrypted_request_data):
        return protected_response(user, {'error': 'error'})
    f = File.objects.get(id=decrypted_request_data['fileID'])
    if f.owner == user:
        data = f.file.read() #in production this would instead be handled by Apache
        f.file.close()
        response = HttpResponse(data, content_type=mimetypes.guess_type(settings.MEDIA_ROOT + f.file.name)[0])
        response['Content-Disposition'] = "attachment; filename={0}".format(f.file)
        response['Content-Length'] = f.file.size
        return response
        #return protected_response(user, {'success': 'True', 'fileID': f.id})
    else:
        try:
            ac = AccessController.objects.get(user=user, original=f)
            data = ac.file.read() #in production this would instead be handled by Apache
            ac.file.close()
            key = ac.key.read() #in production this would instead be handled by Apache
            ac.key.close()
            response = Response({"file": data, "key": key}, content_type=mimetypes.guess_type(settings.MEDIA_ROOT + ac.original.name)[0])
            response['Content-Disposition'] = "attachment; filename={0}".format(ac.file)
            response['Content-Length'] = ac.file.size
            return response
        except:
            return protected_response(user, {'success': 'False', 'fileID': 'You cannot access this file'})


#path('share/', views.api_share, name='api_share'),
@ratelimit(key='ip', rate='1/s')
@define_usage(params={'file_id': 'Int', 'file_key': 'String', 'email': 'String', 'client_msn': 'Integer'}, returns={'success': 'Boolean'})
@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((AllowAny,))
def api_share(request):
    user = custom_auth(request.headers["data"])
    decrypted_request_data = decrypt_request_data(request.data['data'])
    if not check_client_msn(user, decrypted_request_data):
        return protected_response(user, {'error': 'error'})
    f = File.objects.get(id=decrypted_request_data['fileID'])
    if f.owner == user:
        ac = AccessController(user=User.objects.get(username=decrypted_request_data["username"]), original=f, file=request.FILES.get('file'), key=request.FILES.get('keyfile'))
        ac.save()
    return protected_response(user, {'success': 'True'})


#path('revoke/', views.api_revoke, name='api_revoke'),
@ratelimit(key='ip', rate='1/s')
@define_usage(params={'file_id': 'Int', 'email': 'String', 'client_msn': 'Integer'}, returns={'success': 'Boolean'})
@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((AllowAny,))
def api_revoke(request):
    user = custom_auth(request.headers["data"])
    decrypted_request_data = decrypt_request_data(request.data['data'])
    if not check_client_msn(user, decrypted_request_data):
        return protected_response(user, {'error': 'error'})
    f = File.objects.get(id=decrypted_request_data['fileID'])
    if f.owner == user:
        ac = AccessController.objects.get(user=User.objects.get(username=decrypted_request_data["username"]), original=f)
        ac.file.delete()
        ac.delete()
    return protected_response(user, {'success': 'True'})
