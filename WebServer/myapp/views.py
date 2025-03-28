from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
import json
import joblib
import os
import random
import time
import re

from django.conf import settings
import pandas as pd

# from Cyber.AI_Model_Trainer import AnomalyDetector, DataLoader, DataPreprocessor
from AI_Scripts.AI_Model_Trainer import  AnomalyDetector, DataLoader, DataPreprocessor
detector = AnomalyDetector()

timings = {
    "web_server_boot": 0,
    "ai_training": 0,
    "request_loading": 0,
    "request_processing": 0,
    "data_appending": 0
}

def start_timer():
    return time.time()

def end_timer(start_time, operation):
    end_time = time.time()
    elapsed_time = end_time - start_time
    timings[operation] = elapsed_time
    return elapsed_time

def get_timings():
    return timings
 
     
# Define a function for
# validate an Ip address
def check(Ip): 
    regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    # pass the regular expression
    # and the string in search() method
    return re.search(regex, Ip)


ai_training_start = start_timer()
#! WITH TRAINED MODEL
MODEL_PATH = settings.BASE_DIR /  "models" 


# if os.path.exists(MODEL_PATH):
# model = joblib.load(MODEL_PATH / "network_packet_classifier_04_03_2025_17_53_07.pkl" )
# else:
#     raise FileNotFoundError(f"Model file not found at {MODEL_PATH}")


AI_Scripts_dir = settings.BASE_DIR / "AI_Scripts"
# trained_model = AI_Scripts_dir / "network_packet_classifier.pkl"
# trained_model_path = AI_Scripts_dir / "network_packet_classifier.joblib"
# trained_model = joblib.load(trained_model_path)

#! WITH UNTRAINED MODEL
datasets_dir = AI_Scripts_dir / "datasets"    
train_file_path = datasets_dir / "good8k_syn1k_buff1k.json"
test_file_path = datasets_dir / "All_Malware_Even.json"

train_df = DataPreprocessor(DataLoader.transform_json_to_df(train_file_path)).preprocess_df()
test_df = DataPreprocessor(DataLoader.transform_json_to_df(test_file_path)).preprocess_df()
# Train and predict using the model

train_df = train_df.dropna()
test_df = test_df.dropna()
detector = AnomalyDetector()
detector.load_and_train_model(train_df)
test_results = detector.predict_model(test_df)
end_timer(ai_training_start, "ai_training")

results = ""
live_data = []
packet_anomaly_count_dict = {"anomaly": 0, "normal": 0}

def random_one():
    return int(random.choice([1, -1]))

@csrf_exempt
def ipv4_data(request):
    global live_data  # Access the global variable
    
    request_loading_start = start_timer()
    if request.method == "POST":
        try:
            # Parse incoming JSON data
            data = json.loads(request.body.decode("utf-8"))
            #! THIS IS WHERE THE AI CODE WILL LIVE AND MUTATE THE DATA
            if data:
                end_timer(request_loading_start, "request_loading")
                request_processing = start_timer()
                results = detector.predict(data)
                
                data["anomaly_score"] = int(results[0])
                # data["anomaly_score"] = random_one()
                
                if data["anomaly_score"] == 1:
                    packet_anomaly_count_dict["anomaly"] += 1
                    print("\n\n\nTHIS IS AN ANOMLY\n\n\n")
                else:
                    packet_anomaly_count_dict["normal"] += 1
                    print("\n\n\nTHIS IS NORMAL\n\n\n")
                data["anomaly_normal_count"] = packet_anomaly_count_dict
                end_timer(request_processing, "request_processing")
                
                # print(data)

            live_data.append(data)
            # print(f"\nTIMINGS: \n {get_timings()}  \n\n\n")
            
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
    



@csrf_exempt
def start_packet_scan(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            dest_ip = data.get('dest_ip', '')
            if check(dest_ip):
                print(f"Packet Scan Started for IP: {dest_ip}")
            
                return JsonResponse({
                    'status': 'success',
                    'message': 'Packet Scan Started',
                    'destination_ip': dest_ip
                })
        except json.JSONDecodeError:
            return JsonResponse({'status': 'error', 'message': 'Invalid JSON'}, status=400)
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=400)
