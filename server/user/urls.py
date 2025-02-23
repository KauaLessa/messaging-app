from django.urls import path
from . import views
from rest_framework.authtoken.views import obtain_auth_token


urlpatterns = [
    path('create', views.CreateUser.as_view(), name='create-user'),
    path('sign_in', obtain_auth_token, name='sign-in'), 
    path('change_email', views.ChangeEmail.as_view(), name='change-email'), 
    path('delete_user', views.DeleteUser.as_view(), name='delete-user'), 
    path('change_password', views.ChangePassword.as_view(), name='change-password'), 
    path('logout', views.Logout.as_view(), name='logout'), 
]