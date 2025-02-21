from django.urls import path
from . import views
from rest_framework.authtoken.views import obtain_auth_token

DEFAULT = 'api/user'

urlpatterns = [
    path(DEFAULT+'/create', views.CreateUser.as_view(), name='create-user'),
    path(DEFAULT+'/sign_in', obtain_auth_token), 
    path(DEFAULT+'/change_email', views.ChangeEmail.as_view(), name='change-email'), 
    path(DEFAULT+'/delete_user', views.DeleteUser.as_view(), name='delete-user'), 
    path(DEFAULT+'/change_password', views.ChangePassword.as_view(), name='change-password'), 
    path(DEFAULT+'/logout', views.Logout.as_view(), name='logout'), 
]