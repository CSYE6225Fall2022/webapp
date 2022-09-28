from django.test import TestCase
from . import views
from django.urls import reverse


# Create your tests here.
class ModalTests(TestCase):
    def test_health(self):
        response = self.client.get(reverse('health'))
        print(response)
        self.assertEqual(response.status_code,200)
