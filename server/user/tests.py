from django.urls import include, path, reverse
from rest_framework.test import APITestCase, URLPatternsTestCase
from rest_framework import status
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from django.contrib.auth.hashers import check_password
from rest_framework.authtoken.models import Token

#TODO: Testar casos indevidos

class UserTestBase(APITestCase, URLPatternsTestCase):
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

class UserTestsSuccess(UserTestBase):
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
        self.assertIsNotNone(User.objects.filter(username=user_data['username']).first())

    def test_change_email_success(self):
        url = reverse('change-email')
        new_email = 'new@gmail.com'
        response = self.client.patch(url, data={'new_email':new_email}) 

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


class UserTestFail(UserTestBase):
    def setUp(self):
        super().setUp()
        self.user_data = {
            'username':'JonhDoe', 
            'email':'test@gmail.com', 
            'password':'password'
        }

    def test_create_user_blank(self):
        url = reverse('create-user')
        response = self.client.post(
            url,
            data={
                'username':'', 
                'email':'',
                'password':''
            }
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(set(response.data.keys()), set(['username', 'email', 'password']))

    def test_create_user_password_lower_bound(self):
        url = reverse('create-user')
        self.user_data['password'] = 'pass'
        response = self.client.post(url, data=self.user_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(set(response.data.keys()), set(['password']))

    def test_create_user_invalid_email(self):
        url = reverse('create-user')
        self.user_data['email'] = 'invalidemail'
        response = self.client.post(url, data=self.user_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(set(response.data.keys()), set(['email']))

    def test_change_email_blank(self):
        url = reverse('change-email')
        response = self.client.patch(url, data={'new_email':''})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(set(response.data.keys()), set(['email']))

    def test_change_email_invalid(self):
        url = reverse('change-email')
        response = self.client.patch(url, {'new_email':'invalidemail'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(set(response.data.keys()), set(['email']))

    def test_change_password_wrong_current_password(self):
        url = reverse('change-password')
        response = self.client.post(
            url,
            data={
                'current_password':'wrong_password',
                'new_password':'newpassword',
                'repeat_password':'newpassword'
            }
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(set(response.data.keys()), set(['current_password']))

    def test_change_password_invalid_new_password(self):
        url = reverse('change-password')
        response = self.client.post(
            url,
            data={
                'current_password':self.user_data['password'],
                'new_password':'pass', 
                'repeat_password':'pass'
            }
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(set(response.data.keys()), set(['password']))

    def test_change_password_not_matching(self):
        url = reverse('change-password')
        response = self.client.post(
            url,
            data = {
                'current_password':self.user_data['password'],
                'new_password':'newpassword',
                'repeat_password':'not_macthing'
            }
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(set(response.data.keys()), set(['error']))


    def test_delete_user_wrong_password(self):
        url = reverse('delete-user')
        response = self.client.delete(url, data={'password':'wrong password'})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(set(response.data.keys()), set(['error']))

    
