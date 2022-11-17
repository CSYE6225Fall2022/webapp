from django.urls import path,re_path

from . import views
from .views import FileUploadView
from .views import Myendpointview
from .views import Myemailverify

urlpatterns = {
    path('documents/', FileUploadView.as_view(),name='documents'),
    path('account/', views.index, name='index'),
    path('account/<uuid:id>/', views.self, name='self'),
    re_path(r'^documents/(?P<id>.*)$',Myendpointview.as_view()),
    path('verifyUserEmail/', Myemailverify.as_view()),
}
