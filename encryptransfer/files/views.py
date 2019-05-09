from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.parsers import FileUploadParser
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.authentication import SessionAuthentication, BasicAuthentication, TokenAuthentication
from rest_framework.reverse import reverse
from rest_framework.authtoken.models import Token
from rest_framework.status import HTTP_400_BAD_REQUEST
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from .decorators import define_usage
from .models import File, AccessController, Profile

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256256


#path('/', views.api_index, name='api_index'),
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


# Encrypt request.data and Response

#path('signup/', views.api_signup, name='api_signup'),
@define_usage(params={"email": "String", "username": "String", "password": "String"},
              returns={'authenticated': 'Bool', 'token': 'Token String'})
@api_view(["POST"])
@permission_classes((AllowAny,))
def api_signup(request):
    try:
        email = request.data['email']
        username = request.data['username']
        password = request.data['password']
    except:
        return Response({'error': 'Please provide correct email, username, and password'},
                        status=HTTP_400_BAD_REQUEST)

    # encrypting request.data with RSA
    h_request = SHA256.new(request.data)
    enc_key_request = RSA.importKey('pubkey')
    cipher_request = PKCS1_v1_5.new(enc_key_request)
    enc_request_RSA = cipher_request.encrypt(request.data+h_request.digest())

    user = User.objects.create_user(username, email, password)
    user.save()
    user = authenticate(username=username, password=password)
    user_profile = Profile(user=user, server_msn=0, client_msn=0)
    user_profile.save()
    if user is not None:
        token, _ = Token.objects.get_or_create(user=user)

        # encrypting true response
        true_response_dict = {'authenticated': True, 'token': "Token " + token.key}
        true_response_h = SHA256.new(true_response_dict)
        true_response_enc_key = RSA.importKey('pubkey2')
        true_response_cipher = PKCS1_v1_5.new(true_response_enc_key)
        true_response_enc_RSA = true_response_cipher.encrypt(true_response_dict + true_response_h.digest())

        return Response({'authenticated': True, 'token': "Token " + token.key})
    else:

        # encrypting false response
        false_response_dict = {'authenticated': False, 'token': None}
        false_response_h = SHA256.new(false_response_dict)
        false_response_enc_key = RSA.importKey('pubkey3')
        false_response_cipher = PKCS1_v1_5.new(false_response_enc_key)
        false_response_enc_RSA = false_response_cipher.encrypt(false_response_dict + false_response_h.digest())

        return Response({'authenticated': False, 'token': None})


#path('signin/', views.api_signin, name='api_signin'),
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

    # encrypting request.data with RSA
    h_request = SHA256.new(request.data)
    enc_key_request = RSA.importKey('pubkey4')
    cipher_request = PKCS1_v1_5.new(enc_key_request)
    enc_request_RSA = cipher_request.encrypt(request.data+h_request.digest())

    if user is not None:
        token, _ = Token.objects.get_or_create(user=user)

        # encrypting true response
        true_response_dict = {'authenticated': True, 'token': "Token " + token.key}
        true_response_h = SHA256.new(true_response_dict)
        true_response_enc_key = RSA.importKey('pubkey5')
        true_response_cipher = PKCS1_v1_5.new(true_response_enc_key)
        true_response_enc_RSA = true_response_cipher.encrypt(true_response_dict + true_response_h.digest())

        return Response({'authenticated': True, 'token': "Token " + token.key})
    else:
        false_response_dict = {'authenticated': False, 'token': None}
        false_response_h = SHA256.new(false_response_dict)
        false_response_enc_key = RSA.importKey('pubkey6')
        false_response_cipher = PKCS1_v1_5.new(false_response_enc_key)
        false_response_enc_RSA = false_response_cipher.encrypt(false_response_dict + false_response_h.digest())

        return Response({'authenticated': False, 'token': None})


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
@define_usage(params={'file': 'File', 'client_msn': 'Integer'}, returns={'success': 'Boolean'})
@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((IsAuthenticated,))
def api_upload(request):
    if not check_client_msn(request):
        return protected_response(request, {'error': 'error'})
    f = request.data['file']
    new_file = File(request.user, f)
    new_file.save()
    return protected_response(request, {'success', 'True'})


#path('download/', views.api_download, name='api_download'),
@define_usage(params={'file_id': 'Int', 'client_msn': 'Integer'}, returns={'file': 'File'})
@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((IsAuthenticated,))
def api_download(request):
    if not check_client_msn(request):
        return protected_response(request, {'error': 'error'})
    pass


#path('share/', views.api_share, name='api_share'),
@define_usage(params={'file_id': 'Int', 'file_key': 'String', 'user_email': 'String', 'client_msn': 'Integer'}, returns={'file_metadata': 'Dict'})
@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((IsAuthenticated,))
def api_share(request):
    if not check_client_msn(request):
        return protected_response(request, {'error': 'error'})
    pass


#path('revoke/', views.api_revoke, name='api_revoke'),
@define_usage(params={'file_id': 'Int', 'user_email': 'String', 'client_msn': 'Integer'}, returns={'file_metadata': 'Dict'})
@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((IsAuthenticated,))
def api_revoke(request):
    if not check_client_msn(request):
        return protected_response(request, {'error': 'error'})
    pass
