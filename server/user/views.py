from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import UserSerializer
from rest_framework import status
from django.contrib.auth.hashers import check_password
from rest_framework.permissions import IsAuthenticated

#TODO: Criar view para resgatar usuários do banco de dados

class CreateUser(APIView):
    def post(self, request, format=None):
        serializer = UserSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        serializer.save()

        return Response(serializer.data, status=status.HTTP_201_CREATED)

class DeleteUser(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, format=None):
        if check_password(request.data['password'], request.user.password):
            username = request.user.username
            request.user.delete()
            return Response({'message':f'User {username} deleted successfully'}, status=status.HTTP_200_OK)
        
        return Response({"error":"Wrong password."}, status=status.HTTP_400_BAD_REQUEST)
    
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
                return Response(data={'message':'Password changed'}, status=status.HTTP_200_OK)
            
            # new password is invalid
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({'error':'Wrong password. Please try again.'}, status=status.HTTP_400_BAD_REQUEST)

class ChangeEmail(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request):
        serializer = UserSerializer(instance=request.user, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response({"new_email":request.user.email}, status.HTTP_200_OK)
        
        # new email is invalid
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class Logout(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        username = request.user.username
            
        request.user.auth_token.delete()

        return Response({"message": "You are now logged out", "username": username}, status=status.HTTP_200_OK)