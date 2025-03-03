from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
import json
from django.shortcuts import render
import joblib
import os
import joblib

from django.conf import settings
import pandas as pd
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from Cyber.AI_Model_Trainer import AnomalyDetector, DataLoader, DataPreprocessor

live_data = []
detector = AnomalyDetector()

# Get the absolute path to the Cyber directory
cyber_dir = Path(__file__).resolve().parent

#! WITH UNTRAINED MODEL
# datasets_dir = settings.BASE_DIR / "datasets"

# # Construct paths to the datasets
# good_packets_path = datasets_dir / "goodPackets.json"
# buffer_overflow_path = datasets_dir / "BufferOverflowPackets.json"
# syn_flood_path = datasets_dir / "SYNFloodPacket.json"

# good_df = DataPreprocessor(DataLoader.transform_json_to_df(good_packets_path)).preprocess_df()
# buffer_df = DataPreprocessor(DataLoader.transform_json_to_df(buffer_overflow_path)).preprocess_df()
# syn_flood_df = DataPreprocessor(DataLoader.transform_json_to_df(syn_flood_path)).preprocess_df()

# good_train_df, good_test_df = detector.split_training_testing_df(good_df)
# buffer_train_df, buffer_test_df = detector.split_training_testing_df(buffer_df)
# syn_flood_train_df, syn_flood_test_df = detector.split_training_testing_df(syn_flood_df)

# train_df = pd.concat([good_train_df, buffer_train_df, syn_flood_train_df], ignore_index=True)
# test_df = pd.concat([good_test_df, buffer_test_df, syn_flood_test_df], ignore_index=True)

# detector.load_and_train_model(train_df)
# test_results = detector.predict(test_df)

#! WITH TRAINED MODEL
models_dir = settings.BASE_DIR / "models"

model_path = models_dir / "network_packet_classifier.pkl" 
model = joblib.load(model_path)


results = ""
@csrf_exempt
def ipv4_data(request):
    global live_data  # Access the global variable
    
    if request.method == "POST":
        try:
            # Parse incoming JSON data
            data = json.loads(request.body.decode("utf-8"))
            #! THIS IS WHERE THE AI CODE WILL LIVE AND MUTATE THE DATA
            if data:
                # results = detector.predict(data)
                results = model.predict(data)
            print(result)

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
    
