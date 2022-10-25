from django.urls import path,re_path

from . import views
from .views import FileUploadView

urlpatterns = {
    path('', views.index, name='index'),
    path('<uuid:id>/', views.self, name='self'),
    path('', views.docs, name='docs'),
    re_path(r'^upload/(?P<filename>[^/]+)$', FileUploadView.as_view())
    # path('self/<uuid:id>', views.doc, name='doc'),
}
