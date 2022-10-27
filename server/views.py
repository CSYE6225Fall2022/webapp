from rest_framework import status as sta
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status, views


# Create your views
#here.
class Health(views.APIView):

    def get(self,request):
        if request.method == 'GET':
            return Response(status=sta.HTTP_200_OK)



