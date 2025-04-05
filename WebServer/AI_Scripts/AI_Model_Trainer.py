# Importing necessary libraries
import pandas as pd
import json
import numpy as np
from ipaddress import ip_address
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from scipy.stats import entropy
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
        # Remove cols with missing data
        cols_to_remove = [
            "ipv4data.type", "ipv4data.protocol", "tcpdata.urgent_pointer", "tcpdata.timestamp", "ipv4data.version",
            "tcpdata.destination_ip", "tcpdata.source_ip", "ipv4data.flags", "ipv4data.options", "ipv4data.padding"
        ]
        self.df.drop(cols_to_remove, axis=1, inplace=True, errors='ignore')
        # Rename cols and organizing sequence for readability
        new_col_names = {
            'ipv4data.source': 'Source', 'ipv4data.destination': 'Destination', 'tcpdata.flags':'Flags','ipv4data.frag_offset': 'FragOffset','ipv4data.ihl': 'IHL', 
            'ipv4data.length': 'Packet_Length', 'ipv4data.base_layer.Contents': 'Contents', 'ipv4data.base_layer.Payload': 'Payload',
            'ipv4data.checksum': 'IPVChecksum', 'ipv4data.ttl': 'TTL', 'ipv4data.tos': 'TOS', 'ipv4data.payload': 'IPPayload', 
            'ipv4data.timestamp': 'Time', 'tcpdata.source_port': 'SourcePort', 'tcpdata.destination_port': 'DestinationPort',
            'tcpdata.sequence_number': 'SeqNum', 'tcpdata.acknowledgment_number': 'AckNum', 'tcpdata.data_offset': 'DataOffset', 
            'tcpdata.window_size': 'WindowSize', 'tcpdata.checksum': 'TCPChecksum', 'tcpdata.payload': 'TCPPayload', 'tcpdata.payload_hex': 'PayloadHex'
        }
        self.df.rename(columns=new_col_names, inplace=True)
        new_order = [
            'Time', 'Source', 'Destination', 'Packet_Length', 'Flags', 'FragOffset', 'IHL', 'Contents', 'Payload', 'IPVChecksum','TTL', 'TOS', 'IPPayload', 
            'SourcePort', 'DestinationPort', 'SeqNum', 'AckNum', 'DataOffset','WindowSize', 'TCPChecksum', 'TCPPayload', 'PayloadHex'
        ]
        self.df = self.df[[col for col in new_order if col in self.df.columns]]
        # Convert Time col to datetime format
        self.df['Time'] = pd.to_datetime(self.df['Time'])
        # Fill missing values with appropriate defaults
        self.df.fillna({
            'Source': '0.0.0.0',
            'Destination': '0.0.0.0',
            'SourcePort': 0,
            'DestinationPort': 0,
            'Packet_Length': self.df['Packet_Length'].median(),
            'FragOffset': 0,
            'IHL': self.df['IHL'].median(),
            'IPVChecksum': 0,
            'TTL': self.df['TTL'].median(),
            'TOS': 0,
            'SeqNum': 0,
            'AckNum': 0,
            'DataOffset': self.df['DataOffset'].median(),
            'WindowSize': self.df['WindowSize'].median(),
            'TCPChecksum': 0
        }, inplace=True)
        
        # Preprocessing: convert categorical data to numerical data
        self.df['Source'] = self.df['Source'].apply(self.convert_IP_to_int)
        self.df['Destination'] = self.df['Destination'].apply(self.convert_IP_to_int)
        self.df['SourcePort'] = self.df['SourcePort'].apply(self.extract_port_number)
        self.df['DestinationPort'] = self.df['DestinationPort'].apply(self.extract_port_number)
        
        # Feature Engineering: adding new relevant features
        self.df['TCPPayload_Length'] = self.df['TCPPayload'].apply(lambda x: len(str(x)) if pd.notna(x) else 0)
        self.df['Payload_Length'] = self.df['Payload'].apply(lambda x: len(str(x)) if pd.notna(x) else 0)
        self.df['Payload_Entropy'] = self.df['Payload'].apply(self.calculate_entropy)
        self.df = self.add_rolling_stats(self.df, cols=['Packet_Length', 'Payload_Length', 'TCPPayload_Length'], window=5)
        '''
        flag_columns = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]
        # Create empty flag columns
        for flag in flag_columns:
            self.df[flag] = self.df['Flags'].apply(lambda x: 1 if re.search(fr"{flag}:true", x) else 0)
        '''
        # Drop original 'Flags' column after encoding
        self.df.drop(columns=['Flags'], inplace=True)
        #print(self.df.iloc[:, -8:].value_counts())
        
        # Remove another set of irrelevant cols
        cols_to_prep_later = ['Contents', 'Payload', 'IPPayload', 'TCPPayload', 'PayloadHex']
        self.df.drop(cols_to_prep_later, axis=1, inplace=True, errors='ignore')
        cols_to_ignore = ['Source', 'Destination', 'IHL', 'FragOffset', 'TTL', 'TOS', 'AckNum', 'DataOffset']
        self.df.drop(cols_to_ignore, axis=1, inplace=True, errors='ignore')
        
        # Convert datetime to seconds from start and engineer new feature Delta Time
        self.df["Time"] = (self.df["Time"] - self.df["Time"].min()).dt.total_seconds()
        self.df["Delta Time"] = self.df["Time"].diff().fillna(0)

        return self.df
    
    # Calculates entropy(randomness of characters in the str) of each value in the Payload column
    # Higher entropy means more randomness; lower entropy suggests repetition
    @staticmethod
    def calculate_entropy(payload):
        if not isinstance(payload, str) or len(payload) == 0:
            return 0 # indicating no entropy
        value, counts = np.unique(list(payload), return_counts=True)
        return entropy(counts, base=2)

    # Use ip_address to convert categorical value to numerical value
    @staticmethod
    def convert_IP_to_int(ip):
        try:
            # Design issue: using log1p even tho it's costly bc compresses the 
            # values and prevents large values from disproportionately influencing the model.
            return np.log1p(int(ip_address(ip)))
        except ValueError:
            return -1

    # Extract numerical value only from port number
    @staticmethod
    def extract_port_number(value):
        return int(''.join(filter(str.isdigit, str(value))))
    
    # Generate rolling stats for a given feature (mean, std, min, max)
    @staticmethod
    def add_rolling_stats(df, cols, window=3):
        for col in cols:
            df[f'Rolling_Mean_{col}'] = df[col].rolling(window=window, min_periods=1).mean()
            df[f'Rolling_Std_{col}'] = df[col].rolling(window=window, min_periods=1).std()
            df[f'Rolling_Min_{col}'] = df[col].rolling(window=window, min_periods=1).min()
            df[f'Rolling_Max_{col}'] = df[col].rolling(window=window, min_periods=1).max()
        return df

class AnomalyDetector:
    def __init__(self, n_estimators=100,contamination="auto"):
        self.model = IsolationForest(n_estimators=n_estimators, contamination=contamination, random_state=42)
        self.scaler = StandardScaler()
    def load_and_train_model(self, train_df):
        X = train_df.drop(columns=["Time"], errors='ignore')
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
    
    def predict_model(self, df):
        y = df.drop(columns=["Time"], errors='ignore')
        y_scaled = self.scaler.transform(y)
        predictions_lst = self.model.predict(y_scaled)
        return predictions_lst
    
    def risk_scoring(self, json_input, low_threshold=30, high_threshold=70):
        if isinstance(json_input, str):
            if os.path.exists(json_input):  # Check if it's a file path
                df = DataPreprocessor(DataLoader.transform_json_to_df(json_input)).preprocess_df()
        elif isinstance(json_input, dict):       
            json_df = pd.json_normalize(json_input)
            df =  DataPreprocessor(json_df).preprocess_df()

        elif isinstance(json_input, pd.DataFrame): 
            df = json_input.copy()
        else:
            raise ValueError("Unsupported input type. Must be a DataFrame, JSON file path, or JSON text object.")
        
       
        y = df.drop(columns=["Time", "true_label"], errors='ignore')
        y_scaled = self.scaler.transform(y)  # Transform using the trained scaler
        anomaly_scores = self.model.decision_function(y_scaled)  # Decision function for anomaly scoring
        predictions = self.model.predict(y_scaled)  # 1 for normal, -1 for anomaly

        # Normalize the anomaly scores to a scale of 0-100
        min_score, max_score = min(anomaly_scores), max(anomaly_scores)
        risk_scores = (anomaly_scores - min_score) / (max_score - min_score) * 100  # Scale to [0, 100]
        
        # Apply risk labeling based on the defined thresholds
        risk_labels = []
        for score in risk_scores:
            if score < low_threshold:
                risk_labels.append("low_risk")
            elif score >= low_threshold and score <= high_threshold:
                risk_labels.append("medium_risk")
            else:
                risk_labels.append("high_risk")

        # Prepare the output DataFrame with results
        results_df = pd.DataFrame({
            "Anomaly Score": predictions,
            "Risk Label": risk_labels  # New column for risk labels
        })

        return results_df

    def predict(self, json_input):
        # if isinstance(json_input, pd.DataFrame):
        #     json_df = json_input
        if isinstance(json_input, str):
            if os.path.exists(json_input):  # Check if it's a file path
                json_df = DataPreprocessor(DataLoader.transform_json_to_df(json_input)).preprocess_df()
        elif isinstance(json_input, dict):       
            #print(f'\n\n\n\n\n{json_input}\n\n\n\n')
            json_df = pd.json_normalize(json_input)
        else:
            raise ValueError("Unsupported input type. Must be a DataFrame, JSON file path, or JSON text object.")
        
        preprocessor = DataPreprocessor(json_df)
        df = preprocessor.preprocess_df()
        y = df.drop(columns=["Time"], errors='ignore')
        y_scaled = self.scaler.transform(y)
        predictions = self.model.predict(y_scaled)
        return predictions
        
    def calculate_true_labels(self, test_df):
        test_df["True Labels"] = np.where((test_df["Payload_Length"].fillna(0) <= 1460) | 
            (test_df["Delta Time"].fillna(0) > 1), 0, 1)
        test_df["True Labels"] = test_df["True Labels"].astype(int)  
        return test_df["True Labels"]
# Load and preprocess data
if __name__ == '__main__':
    BASE_DIR = Path(__file__).resolve().parent  # Gets the directory of the script
    datasets_dir = BASE_DIR / "datasets"    
    train_file_path = datasets_dir / "good8k_syn1k_buff1k.json"
    test_file_path = datasets_dir / "All_Malware_Even.json"
    
    train_df = DataPreprocessor(DataLoader.transform_json_to_df(train_file_path)).preprocess_df()
    test_df = DataPreprocessor(DataLoader.transform_json_to_df(test_file_path)).preprocess_df()
    
    # Train and predict using the model
    train_df = train_df.dropna()
    test_df = test_df.dropna()
    detector = AnomalyDetector()
    detector.load_and_train_model(train_df)
    test_results = detector.risk_scoring(test_df)
    test_results['Anomaly Score'] = test_results['Anomaly Score'].map({-1: 0, 1: 1})
    true_results = detector.calculate_true_labels(test_df)
    predictions = test_results["Anomaly Score"]
    print("Predictions: ", predictions)
    print("Actuals: ", true_results)
    print("True labels distribution:\n", true_results.value_counts())
    print("Predicted labels distribution:\n", predictions.value_counts())
    print(classification_report(true_results, predictions))
    print(confusion_matrix(true_results, predictions)) # lots of false negatives
    print(test_results['Risk Label'].value_counts())

    