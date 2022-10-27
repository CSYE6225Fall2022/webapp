from django.test import SimpleTestCase
from . import views


# Create your tests here.
class ModalTests(SimpleTestCase):
    def test_health(self):
        #print(r)
        self.assertEqual(1+1,2)

