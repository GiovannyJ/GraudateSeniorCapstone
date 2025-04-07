from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
import json
import joblib
import os
import random
import time
import re
import socket

from django.conf import settings
import pandas as pd

from AI_Scripts.AI_Model_Trainer import  AnomalyDetector, DataLoader, DataPreprocessor
from ProcessRunner.run import ProcessRunner



#* HELPER FUNCTIONS 
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

def check(Ip): 
    regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    return re.search(regex, Ip)


def random_one():
    return int(random.choice([1, -1]))


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('10.255.255.255', 1))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    return local_ip


USER_LOCAL_IP = get_local_ip()

detector = AnomalyDetector()
MalPacket_procRunner = ProcessRunner("malpacket")
PacketSniffer_procRunner = ProcessRunner("packetsniffer")


ai_training_start = start_timer()
#! WITH TRAINED MODEL
MODEL_PATH = settings.BASE_DIR /  "models" 
AI_Scripts_dir = settings.BASE_DIR / "AI_Scripts"

#! WITH UNTRAINED MODEL
datasets_dir = AI_Scripts_dir / "datasets"    
train_file_path = datasets_dir / "good8k_syn1k_buff1k.json"
test_file_path = datasets_dir / "All_Malware_Even.json"

train_df = DataPreprocessor(DataLoader.transform_json_to_df(train_file_path)).preprocess_df()
test_df = DataPreprocessor(DataLoader.transform_json_to_df(test_file_path)).preprocess_df()

train_df = train_df.dropna()
test_df = test_df.dropna()
detector = AnomalyDetector()
detector.load_and_train_model(train_df)
test_results = detector.predict_model(test_df)
end_timer(ai_training_start, "ai_training")

results = ""
live_data = []
packet_anomaly_count_dict = {"anomaly": 0, "normal": 0, 
                             "high_risk": 0, "medium_risk": 0, "low_risk": 0}



@csrf_exempt
# def ipv4_data(request):
#     global live_data  # Access the global variable
    
#     request_loading_start = start_timer()
#     if request.method == "POST":
#         try:
#             # Parse incoming JSON data
#             data = json.loads(request.body.decode("utf-8"))
#             #! THIS IS WHERE THE AI CODE WILL LIVE AND MUTATE THE DATA
#             if data:
#                 end_timer(request_loading_start, "request_loading")
#                 request_processing = start_timer()
#                 results = detector.predict(data)
                
#                 data["anomaly_score"] = int(results[0])
#                 # data["anomaly_score"] = random_one()
                
#                 if data["anomaly_score"] == 1:
#                     packet_anomaly_count_dict["anomaly"] += 1
#                     print("\n\n\nTHIS IS AN ANOMLY\n\n\n")
#                 else:
#                     packet_anomaly_count_dict["normal"] += 1
#                     print("\n\n\nTHIS IS NORMAL\n\n\n")
#                 data["anomaly_normal_count"] = packet_anomaly_count_dict
#                 end_timer(request_processing, "request_processing")
                
#                 # print(data)

#             live_data.append(data)
#             # print(f"\nTIMINGS: \n {get_timings()}  \n\n\n")
            
#             return JsonResponse({"message": "IPv4 data received successfully!"}, status=200)
        
#         except json.JSONDecodeError:
#             return JsonResponse({"error": "Invalid JSON"}, status=400)
    
#     return JsonResponse({"error": "Invalid request method"}, status=405)

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
                results_df = detector.risk_scoring(data)
                
                data["user_local_ip"] = USER_LOCAL_IP
                if not results_df.empty:
                    data["anomaly_score"] = int(results_df.iloc[0]["Anomaly Score"])  # Get prediction
                    data["risk_label"] = results_df.iloc[0]["Risk Label"]  # Get risk label
                
                if data["anomaly_score"] == 1:
                    packet_anomaly_count_dict["anomaly"] += 1
                    print("\n\n\nTHIS IS AN ANOMALY\n\n\n")
                elif data["anomaly_score"] == -1:
                    packet_anomaly_count_dict["normal"] += 1
                    print("\n\n\nTHIS IS NORMAL\n\n\n")
                risk_label = data['risk_label']
                if risk_label in packet_anomaly_count_dict:
                    packet_anomaly_count_dict[risk_label] += 1

                    # print("\n\n\nTHIS IS AN ANOMLY\n\n\n")
                else:
                    packet_anomaly_count_dict["normal"] += 1
                    # print("\n\n\nTHIS IS NORMAL\n\n\n")
                data["anomaly_normal_count"] = packet_anomaly_count_dict
                
                
                
                
            end_timer(request_processing, "request_processing")
            live_data.append(data)
            print("Live Data: ", data)
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
    
    return render(request, 'dashboard.html', {'data': live_data})
    

@csrf_exempt
def start_packet_scan(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            dest_ip = data.get('dest_ip', '')
            sensitivity = data.get('sensitivity', -0.25)
            if check(dest_ip):
                # print(f"Packet Scan Started for IP: {dest_ip}")
                #! CHANGE VALUE ATTRIBUTE FOR RISK SCANNER OVER HERE
                detector.riskThresholds = sensitivity 
                
                PacketSniffer_procRunner.StartProcess(dest_ip)
                
                return JsonResponse({
                    'status': 'success',
                    'message': 'Packet Scan Started',
                    'destination_ip': dest_ip
                })
            else:
                return JsonResponse({'status': 'error', 'message': 'Invalid IP address'}, status=400)
        except json.JSONDecodeError:
            return JsonResponse({'status': 'error', 'message': 'Invalid JSON'}, status=400)
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=400)

@csrf_exempt
def start_simulated_packet_scan(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            sensitivity = data.get('sensitivity', -0.25)
            #! CHANGE VALUE ATTRIBUTE FOR RISK SCANNER OVER HERE
            detector.riskThresholds = sensitivity 

            MalPacket_procRunner.StartProcess()
            
            PacketSniffer_procRunner.StartProcess(USER_LOCAL_IP)
                    
            return JsonResponse({
                'status': 'success',
                'message': 'Simulated Environment Started',
                'user_local_ip': USER_LOCAL_IP,
            })
            
        except json.JSONDecodeError:
            return JsonResponse({'status': 'error', 'message': 'Invalid JSON'}, status=400)
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=400)


@csrf_exempt
def stop_packet_scan(request):
    if request.method == 'POST':
        try:
            MalPacket_procRunner.StopProcess()
            PacketSniffer_procRunner.StopProcess()
                
            return JsonResponse({
                'status': 'success',
                'message': 'Packet Scan Stopped',
            })
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=400)







