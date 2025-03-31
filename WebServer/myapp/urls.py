from django.urls import path
from . import views  # Import from the current app

urlpatterns = [
    path('IPv4Data', views.ipv4_data, name='ipv4_data'),
    path('', views.display_data, name='display_data'),
    path('start-packet-scan/', views.start_packet_scan, name='start_packet_scan'),
    path('start-simulated-packet-scan/', views.start_simulated_packet_scan, name='start_simulated_packet_scan'),
    path('stop-packet-scan/', views.stop_packet_scan, name='stop_packet_scan')
]
