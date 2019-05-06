from django.contrib import admin
from .models import File, AccessController, Profile


class ProfileAdmin(admin.ModelAdmin):
    list_display = [f.name for f in Profile._meta.fields]


class AccessControllerAdmin(admin.ModelAdmin):
    list_display = [f.name for f in AccessController._meta.fields]


class FileAdmin(admin.ModelAdmin):
    list_display = [f.name for f in File._meta.fields]


admin.site.register(Profile, ProfileAdmin)
admin.site.register(AccessController, AccessControllerAdmin)
admin.site.register(File, FileAdmin)
