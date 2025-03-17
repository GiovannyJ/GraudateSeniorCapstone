from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
import json
import joblib
import os
import random

from django.conf import settings
import pandas as pd

# from Cyber.AI_Model_Trainer import AnomalyDetector, DataLoader, DataPreprocessor
from AI_Scripts.AI_Model_Trainer import  AnomalyDetector, DataLoader, DataPreprocessor
detector = AnomalyDetector()

#! WITH TRAINED MODEL
MODEL_PATH = settings.BASE_DIR /  "models" 


# if os.path.exists(MODEL_PATH):
# model = joblib.load(MODEL_PATH / "network_packet_classifier_04_03_2025_17_53_07.pkl" )
# else:
#     raise FileNotFoundError(f"Model file not found at {MODEL_PATH}")


#! WITH UNTRAINED MODEL
AI_Scripts_dir = settings.BASE_DIR / "AI_Scripts"
trained_model = AI_Scripts_dir / "network_packet_classifier.pkl"
'''
# Construct paths to the datasets
good_packets_path = datasets_dir / "goodPackets.json"
buffer_overflow_path = datasets_dir / "BufferOverflowPackets.json"
syn_flood_path = datasets_dir / "SYNFloodPacket.json"

good_df = DataPreprocessor(DataLoader.transform_json_to_df(good_packets_path)).preprocess_df()
buffer_df = DataPreprocessor(DataLoader.transform_json_to_df(buffer_overflow_path)).preprocess_df()
syn_flood_df = DataPreprocessor(DataLoader.transform_json_to_df(syn_flood_path)).preprocess_df()

good_train_df, good_test_df = detector.split_training_testing_df(good_df)
buffer_train_df, buffer_test_df = detector.split_training_testing_df(buffer_df)
syn_flood_train_df, syn_flood_test_df = detector.split_training_testing_df(syn_flood_df)

train_df = pd.concat([good_train_df, buffer_train_df, syn_flood_train_df], ignore_index=True)
test_df = pd.concat([good_test_df, buffer_test_df, syn_flood_test_df], ignore_index=True)

detector.load_and_train_model(train_df)
test_results = detector.predict_model(test_df)

'''


results = ""
live_data = []
packet_anomaly_count_dict = {"anomaly": 0, "normal": 0}

def random_one():
    return int(random.choice([1, -1]))

@csrf_exempt
def ipv4_data(request):
    global live_data  # Access the global variable
    
    if request.method == "POST":
        try:
            # Parse incoming JSON data
            data = json.loads(request.body.decode("utf-8"))
            #! THIS IS WHERE THE AI CODE WILL LIVE AND MUTATE THE DATA
            if data:
                results = detector.predict(data)
                
                # data["anomaly_score"] = int(results[0])
                data["anomaly_score"] = random_one()
                
                if data["anomaly_score"] == 1:
                    packet_anomaly_count_dict["anomaly"] += 1
                else:
                    packet_anomaly_count_dict["normal"] += 1
                data["anomaly_normal_count"] = packet_anomaly_count_dict
                
                
                # print(data)

            #live_data.append(data)
            
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
    # return render(request, 'dashboard.html', {'data': live_data})
    return render(request, 'dynamictest.html', {'data': live_data})
    

