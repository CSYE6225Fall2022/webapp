from rest_framework import status as sta
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status, views
import logging
from django_statsd.clients import statsd
logger = logging.getLogger(__name__)
logger.setLevel("INFO")

# Create your views
#here.
class Health(views.APIView):

    def get(self,request):
        if request.method == 'GET':
            logger.info("GET: Health Check")
            statsd.incr('api.healthz')
            t= statsd.timer('api.healthz').start()
            t.stop()
            #t.start()
            #statsd.timer.stop('api.healthz').stop()

            return Response(status=sta.HTTP_200_OK)



