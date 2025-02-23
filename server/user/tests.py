from django.urls import include, path, reverse
from rest_framework.test import APITestCase, URLPatternsTestCase
from rest_framework import status
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from django.contrib.auth.hashers import check_password
from rest_framework.authtoken.models import Token

#TODO: Testar casos indevidos

class UserTests(APITestCase, URLPatternsTestCase):

    urlpatterns = [
        path('api/user/', include('user.urls')),
    ]

    @classmethod
    def setUpTestData(cls):
        """Cria um usuário que estará disponível em todos os testes desta classe."""

        cls.user = User.objects.create_user(
            username='testuser', 
            email='test@example.com', 
            password='password'
        )
        Token.objects.create(user=cls.user)

    def setUp(self):
        self.client = APIClient()
        self.client.force_authenticate(self.user, self.user.auth_token)

    def test_create_user_success(self):
        url = reverse('create-user')
        user_data = {
                'username':'JonhDoe', 
                'email':'Jonh@gmail.com',
                'password':'password'
            }
        response = self.client.post(url, data=user_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['username'], user_data['username'])
        self.assertEqual(response.data['email'], user_data['email'])
        self.assertIsNotNone(User.objects.get(username=user_data['username']))

    def test_change_email_success(self):
        url = reverse('change-email')
        new_email = 'new@gmail.com'
        response = self.client.patch(url, data={'email':new_email}) 

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {'new_email':new_email})
        self.assertEqual(self.user.email, new_email)
        
    def test_change_password_success(self):
        url = reverse('change-password')
        new_password = 'newpassword'
        response = self.client.post(
            url, data={
                'current_password':'password', 
                'new_password':new_password, 
                'repeat_password':new_password
            }
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {'message':'Password changed'})
        self.assertTrue(check_password(new_password, self.user.password))
        self.assertIsNone(Token.objects.filter(user=self.user).first())

    def test_logout(self):
        url = reverse('logout')
        response = self.client.post(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {"message": "You are now logged out", "username": self.user.username})
        self.assertIsNone(Token.objects.filter(user=self.user).first())

    def test_delete_user_success(self):
        url = reverse('delete-user')
        username = self.user.username
        response = self.client.delete(
            url, 
            data={'password':'password'}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {'message':f'''User {self.user.username} deleted successfully'''})
        self.assertIsNone(User.objects.filter(username=username).first())
