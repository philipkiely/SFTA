"""encryptransfer URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from files import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.api_index, name='api_index'),
    path('signup/', views.api_signup, name='api_signup'),
    path('signin/', views.api_signin, name='api_signin'),
    path('my_files/', views.api_my_files, name='api_my_files'),
    path('my_access/', views.api_my_access, name='api_my_access'),
    path('upload/', views.api_upload, name='api_upload'),
    path('download/', views.api_download, name='api_download'),
    path('share/', views.api_share, name='api_share'),
    path('revoke/', views.api_revoke, name='api_revoke'),
]
