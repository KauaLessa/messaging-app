from django.contrib.auth.models import User
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.renderers import JSONRenderer
from .serializers import UserSerializer
from rest_framework import status
from django.contrib.auth import authenticate
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from django.contrib.auth.hashers import check_password
from rest_framework.permissions import IsAuthenticated

#TODO: Testar ChangePassword, ChangeEmail e DeleteUser
#TODO: Implementar logout automático ao mudar a senha
#TODO: View de logout

class CreateUser(APIView):
    def post(self, request, format=None):
        serializer = UserSerializer(data=request.data)

        if not serializer.is_valid():
            errors = JSONRenderer().render(serializer.errors)
            return Response(errors, status=status.HTTP_400_BAD_REQUEST)

        # creating user
        serializer.save()

        # returning response
        data = JSONRenderer().render(serializer.data)
        return Response(data, status=status.HTTP_201_CREATED)

class DeleteUser(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        user = authenticate(request, **request.data)

        if user:
            username = user.username
            user.delete()
            return Response(f'User {username} deleted successfully', status=status.HTTP_200_OK)
        
        return Response({"error":"Wrong username or password"}, status=status.HTTP_400_BAD_REQUEST)
    
class SignIn(ObtainAuthToken):
    def post(self, request, format=None):
        user = authenticate(request, **request.data)

        if user:
            token, created = Token.objects.get_or_create(user=user)
            return Response(
                {
                    "message":f'{user.username} is now logged in.',
                    "token":token.key
                },
                status=status.HTTP_200_OK
            )
        
        return Response({"error":"Wrong username or password"}, status=status.HTTP_400_BAD_REQUEST)
    
class ChangePassword(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        current_password = request.data['current_password']
        new_password = request.data['new_password']
        repeat_password = request.data['repeat_password']

        if check_password(current_password, request.user.password):
            if repeat_password != new_password:
                return Response({'error': 'Passwords not matching.'}, status=status.HTTP_400_BAD_REQUEST)
            
            serializer = UserSerializer(
                instance=request.user,
                data={'password':new_password},
                partial=True
            )

            if serializer.is_valid():
                serializer.save()
                request.user.auth_token.delete()
                return Response(
                    f'{request.user.username} password changed successfully', status=status.HTTP_200_OK
                )
            
            # new password is invalid
            errors = JSONRenderer().render(serializer.errors)
            return Response(errors, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({'error':'Wrong password. Please try again.'})

class ChangeEmail(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request):
        serializer = UserSerializer(instance=request.user, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response(f'{request.user} new email: {request.user.email}')
        
        # new email is invalid
        errors = JSONRenderer().render(serializer.errors)
        return Response(errors, status=status.HTTP_400_BAD_REQUEST)
    
class Logout(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        username = request.user.username
            
        # Depois, faça o logout
        request.user.auth_token.delete()

        # Retorne a resposta com o nome armazenado anteriormente
        return Response({"detail": "You are now logged out", "username": username})
        



        