from rest_framework import status as sta
from rest_framework.response import Response
from rest_framework.decorators import api_view


# Create your views here.
@api_view(['GET'])
def health(request):
    if request.method == 'GET':
        return Response(status=sta.HTTP_200_OK)



