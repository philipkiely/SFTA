from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.authentication import SessionAuthentication, BasicAuthentication, TokenAuthentication
from rest_framework.reverse import reverse
from rest_framework.authtoken.models import Token
from rest_framework.status import HTTP_400_BAD_REQUEST
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from .decorators import define_usage
from .models import File, AccessController, Profile


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


#path('my_files/', views.api_my_files, name='api_my_files'),
@define_usage(params={'client_msn': 'Integer'}, returns={'file_metadata': 'Dict'})
@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((IsAuthenticated,))
def api_my_files(request):
    if not check_client_msn(request):
        return Response({'error': 'error'})
    file_list = File.objects.get(owner=request.user) # return list of filenames owned by user -- dictionary eventually, return query set
    return Response(file_list)


#path('my_access/', views.api_my_access, name='api_my_access'),
@define_usage(params={'client_msn': 'Integer'}, returns={'file_metadata': 'Dict'})
@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((IsAuthenticated,))
def api_my_access(request):
    if not check_client_msn(request):
        return Response({'error': 'error'})
    access_list = AccessController.objects.get(owner=request.user)
    return Response(access_list)


#path('upload/', views.api_upload, name='api_upload'),
@define_usage(params={'file': 'File', 'client_msn': 'Integer'}, returns={'file_metadata': 'Dict'})
@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((IsAuthenticated,))
def api_upload(request):
    if not check_client_msn(request):
        return Response({'error': 'error'})
    pass


#path('download/', views.api_download, name='api_download'),
@define_usage(params={'file_id': 'Int', 'client_msn': 'Integer'}, returns={'file': 'File'})
@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((IsAuthenticated,))
def api_download(request):
    if not check_client_msn(request):
        return Response({'error': 'error'})
    pass


#path('share/', views.api_share, name='api_share'),
@define_usage(params={'file_id': 'Int', 'file_key': 'String', 'user_email': 'String', 'client_msn': 'Integer'}, returns={'file_metadata': 'Dict'})
@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((IsAuthenticated,))
def api_share(request):
    if not check_client_msn(request):
        return Response({'error': 'error'})
    pass


#path('revoke/', views.api_revoke, name='api_revoke'),
@define_usage(params={'file_id': 'Int', 'user_email': 'String', 'client_msn': 'Integer'}, returns={'file_metadata': 'Dict'})
@api_view(['POST'])
@authentication_classes((SessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((IsAuthenticated,))
def api_revoke(request):
    if not check_client_msn(request):
        return Response({'error': 'error'})
    pass
