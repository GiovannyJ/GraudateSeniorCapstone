# Importing necessary libraries
import pandas as pd
import json
import numpy as np
from ipaddress import ip_address
import joblib
from sklearn.ensemble import IsolationForest
from scipy.stats import entropy
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import os


class DataLoader:
    @staticmethod
    def transform_json_to_df(file_path):
        try:
            # Open the file with UTF-8 encoding
            with open(file_path, 'r', encoding='utf-8') as file:
                data = json.load(file)
            # Convert JSON to DataFrame
            print("[+]File opened")
            df = pd.json_normalize(data)
            print("[+]Data normalized")
            return df
        except Exception as e:
            print(f"Error loading JSON file: {e}")
            return None


class DataPreprocessor:
    """
    Preprocesses DataFrame for model by cleaning, formatting, and feature engineering.
    """
    def __init__(self, df):
        self.df = df

    def preprocess_df(self):
        cols_to_remove = [
            "ipv4data.type", "ipv4data.protocol", "tcpdata.urgent_pointer", "tcp.timestamp", "ipv4data.version",
            "tcpdata.destination_ip", "tcpdata.source_ip", "ipv4data.flags", "tcpdata.flags", "ipv4data.options",
            "ipv4data.padding"
        ]
        self.df.drop(cols_to_remove, axis=1, inplace=True, errors='ignore')

        new_col_names = {
            'ipv4data.source': 'Source', 'ipv4data.destination': 'Destination', 'ipv4data.frag_offset': 'FragOffset',
            'ipv4data.ihl': 'IHL', 'ipv4data.length': 'Length',
            'ipv4data.base_layer.Contents': 'Contents', 'ipv4data.base_layer.Payload': 'Payload',
            'ipv4data.checksum': 'IPVChecksum', 'ipv4data.ttl': 'TTL', 'ipv4data.tos': 'TOS',
            'ipv4data.payload': 'IPPayload', 'ipv4data.timestamp': 'Time',
            'tcpdata.source_port': 'SourcePort', 'tcpdata.destination_port': 'DestinationPort',
            'tcpdata.sequence_number': 'SeqNum', 'tcpdata.acknowledgment_number': 'AckNum',
            'tcpdata.data_offset': 'DataOffset', 'tcpdata.window_size': 'WindowSize',
            'tcpdata.checksum': 'TCPChecksum', 'tcpdata.payload': 'TCPPayload', 'tcpdata.payload_hex': 'PayloadHex'
        }
        self.df.rename(columns=new_col_names, inplace=True)

        new_order = [
            'Time', 'Source', 'Destination', 'Length', 'FragOffset', 'IHL', 'Contents', 'Payload', 'IPVChecksum',
            'TTL', 'TOS', 'IPPayload', 'SourcePort', 'DestinationPort', 'SeqNum', 'AckNum', 'DataOffset',
            'WindowSize', 'TCPChecksum', 'TCPPayload', 'PayloadHex'
        ]
        self.df = self.df[[col for col in new_order if col in self.df.columns]]

        self.df['Time'] = pd.to_datetime(self.df['Time'])
        self.df['Source'] = self.df['Source'].apply(self.convert_IP_to_int)
        self.df['Destination'] = self.df['Destination'].apply(self.convert_IP_to_int)
        self.df['SourcePort'] = self.df['SourcePort'].apply(self.extract_port_number)
        self.df['DestinationPort'] = self.df['DestinationPort'].apply(self.extract_port_number)

        cols_to_prep_later = ['Contents', 'Payload', 'IPPayload', 'TCPPayload', 'PayloadHex']
        self.df.drop(cols_to_prep_later, axis=1, inplace=True, errors='ignore')

        self.df = self.add_rolling_stats(self.df, cols=['Length'], window=5)
        self.df['Burstiness'] = self.df['Rolling_Std_Length'] / self.df['Rolling_Mean_Length'].replace(0, np.nan)

        return self.df

    @staticmethod
    def convert_IP_to_int(ip):
        try:
            return np.log1p(int(ip_address(ip)))
        except ValueError:
            return -1

    @staticmethod
    def extract_port_number(value):
        return int(''.join(filter(str.isdigit, str(value))))

    @staticmethod
    def add_rolling_stats(df, cols, window=3):
        for col in cols:
            df[f'Rolling_Mean_{col}'] = df[col].rolling(window=window, min_periods=1).mean()
            df[f'Rolling_Std_{col}'] = df[col].rolling(window=window, min_periods=1).std()
            df[f'Rolling_Min_{col}'] = df[col].rolling(window=window, min_periods=1).min()
            df[f'Rolling_Max_{col}'] = df[col].rolling(window=window, min_periods=1).max()
        return df

class AnomalyDetector:
    def __init__(self, contamination=0.05):
        self.model = IsolationForest(contamination=contamination, random_state=42)

    def load_and_train_model(self, train_df):
        self.model.fit(train_df.drop(columns=["Time"], errors='ignore'))
    
    def predict(self, json_input):
        if isinstance(json_input, pd.DataFrame):
            json_df = json_input
        elif isinstance(json_input, str):
            if os.path.exists(json_input):  # Check if it's a file path
                json_df = DataPreprocessor(DataLoader.transform_json_to_df(json_input)).preprocess_df()
            else:
                try:
                    json_obj = json.loads(json_input)  # Try parsing as JSON string
                    json_df = pd.json_normalize(json_obj)
                except json.JSONDecodeError:
                    raise ValueError("Invalid JSON string or file path provided.")
        else:
            raise ValueError("Unsupported input type. Must be a DataFrame, JSON file path, or JSON text object.")
        
        predictions = self.model.predict(json_df.drop(columns=["Time"], errors='ignore'))
        return predictions
    

    def split_training_testing_df(self, df):
        split_time = df["Time"].quantile(0.8)
        train_df = df[df["Time"] <= split_time]
        test_df = df[df["Time"] > split_time]
        return train_df, test_df

# Load and preprocess data
if __name__ == '__main__':
    detector = AnomalyDetector()
    
    BASE_DIR = Path(__file__).resolve().parent  # Gets the directory of the script
    datasets_dir = BASE_DIR / "datasets"    
    train_file_path = datasets_dir / "good8k_syn1k_buff1k.json"
    test_file_path = datasets_dir / "All_Malware_Even.json"
    
    train_df = DataPreprocessor(DataLoader.transform_json_to_df(train_file_path)).preprocess_df()
    test_df = DataPreprocessor(DataLoader.transform_json_to_df(test_file_path)).preprocess_df()
    # Train and predict using the model
    train_df = train_df.dropna()
    test_df = test_df.dropna()

    detector.load_and_train_model(train_df)
    test_results = detector.predict(test_df)
    # 6. Save the Model as a .pkl file
    joblib.dump(detector, "network_packet_classifier.pkl")

    
    #print(test_results)
