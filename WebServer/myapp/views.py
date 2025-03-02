from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
import json
from django.shortcuts import render

# In-memory storage for live data (global variable)
live_data = []

@csrf_exempt
def ipv4_data(request):
    global live_data  # Access the global variable
    
    if request.method == "POST":
        try:
            # Parse incoming JSON data
            data = json.loads(request.body.decode("utf-8"))
            #! THIS IS WHERE THE AI CODE WILL LIVE AND MUTATE THE DATA
            
            live_data.append(data)  # Store the latest received data
            
            return JsonResponse({"message": "IPv4 data received successfully!"}, status=200)
        
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)
    
    return JsonResponse({"error": "Invalid request method"}, status=405)

def display_data(request):
    global live_data
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        # Return JSON data for AJAX requests
        return JsonResponse({'data': live_data})
    # Render the template for normal requests
    return render(request, 'display_data.html', {'data': live_data})
    
