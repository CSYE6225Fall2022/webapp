from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('<uuid:id>/', views.self, name='self'),
]
