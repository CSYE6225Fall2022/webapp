from django.urls import path
from . views import Health
urlpatterns = [
    path('',Health.as_view(),name='health'),
]