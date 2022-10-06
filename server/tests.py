from django.test import SimpleTestCase
from . import views
from django.urls import reverse


# Create your tests here.
class ModalTests(SimpleTestCase):
    def test_health(self):
        response = self.client.get(reverse('health'))
        #print(r)
        self.assertEqual(response.status_code,400)

