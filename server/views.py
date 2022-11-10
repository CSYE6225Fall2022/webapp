from rest_framework import status as sta
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status, views
import django_statsd
import logging

logger = logging.getLogger(__name__)
logger.setLevel("INFO")

# Create your views
#here.
class Health(views.APIView):

    def get(self,request):
        if request.method == 'GET':
            logger.info("GET: Health Check")
            django_statsd.incr('api.healthz')

            return Response(status=sta.HTTP_200_OK)



