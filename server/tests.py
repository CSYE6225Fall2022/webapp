from django.test import SimpleTestCase
from . import views
from django.urls import reverse
from . views import Health


# Create your tests here.
class ModalTests(SimpleTestCase):
    def test_health(self):
        #print(r)
        self.assertEqual(1+1,2)

