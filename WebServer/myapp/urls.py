from django.urls import path
from . import views  # Import from the current app

urlpatterns = [
    path('IPv4Data', views.ipv4_data, name='ipv4_data'),
    path('', views.display_data, name='display_data'),
]