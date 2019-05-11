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
from django.conf import settings
from .decorators import define_usage
from .models import File, AccessController, Profile
import os
import mimetypes


#TODO: Rate Limit
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
    try:
        email = request.data['email']
        username = request.data['username']
        password = request.data['password']
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
        return Response({'authenticated': True, 'token': "Token " + token.key})
    else:
        return Response({'authenticated': False, 'token': None})


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
    if user is not None:
        token, _ = Token.objects.get_or_create(user=user)
        return Response({'authenticated': True, 'token': "Token " + token.key})
    else:
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
        response = Response(data, content_type=mimetypes.guess_type(settings.MEDIA_ROOT + f.file.name)[0])
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
