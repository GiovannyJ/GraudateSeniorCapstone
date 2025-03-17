# Importing necessary libraries
import pandas as pd
import json
import numpy as np
from ipaddress import ip_address
import joblib
from sklearn.ensemble import IsolationForest


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
        train_df = train_df.copy()
        if "Time" in train_df.columns:
            train_df["Time"] = (train_df["Time"] - train_df["Time"].min()).dt.total_seconds()
        self.model.fit(train_df.drop(columns=["Time"], errors='ignore'))
    def predict_model(self, df):
        df["anomaly_score"] = self.model.predict(df.drop(columns=["Time"], errors='ignore'))
        return df['anomaly_score'].value_counts()
    
    #! make sure it becomes dataframe as it comes in
    # FIXED: takes in json file path and processes it the same way as training df
    # def predict(self, json_path):
    #     json_df = DataPreprocessor(DataLoader.transform_json_to_df(json_path)).preprocess_df()
    #     if "Time" in json_df.columns:
    #         json_df["Time"] = (json_df["Time"] - json_df["Time"].min()).dt.total_seconds()
    #     json_df["anomaly_score"] = self.model.predict(json_df.drop(columns=["Time"], errors='ignore'))
    #     return json_df['anomaly_score'].value_counts()
    
    def predict(self, input_data):
         """
         Predict anomalies from either a JSON file path or a JSON text object.
 
         Args:
             input_data (str or dict): Either a file path to a JSON file or a JSON text object.
 
         Returns:
             pd.Series: Anomaly scores for the input data.
         """
         # Handle JSON file path
         if isinstance(input_data, str):
             try:
                 with open(input_data, 'r', encoding='utf-8') as file:
                     json_data = json.load(file)
             except Exception as e:
                 print(f"Error loading JSON file: {e}")
                 return None
         # Handle JSON text object
         elif isinstance(input_data, dict):
             json_data = input_data
         else:
             raise ValueError("Input must be either a JSON file path (str) or a JSON text object (dict).")
 
         # Convert JSON to DataFrame
         df = pd.json_normalize(json_data)
         print("[+] Data loaded and normalized")
 
         # Preprocess the DataFrame
         preprocessor = DataPreprocessor(df)
         df = preprocessor.preprocess_df()
 
         # Convert 'Time' to seconds if present
         if "Time" in df.columns:
             df["Time"] = (df["Time"] - df["Time"].min()).dt.total_seconds()
 
         # Predict anomalies
         # anomaly_scores = 
         return self.model.predict(df.drop(columns=["Time"], errors='ignore'))
         # return pd.Series(anomaly_scores, name="anomaly_score")

    def split_training_testing_df(self, df):
        split_time = df["Time"].quantile(0.8)
        train_df = df[df["Time"] <= split_time]
        test_df = df[df["Time"] > split_time]
        return train_df, test_df

# Load and preprocess data
if __name__ == '__main__':
    detector = AnomalyDetector()
    
    good_df = DataPreprocessor(DataLoader.transform_json_to_df('datasets/goodPackets.json')).preprocess_df()
    buffer_df = DataPreprocessor(DataLoader.transform_json_to_df('datasets/BufferOverflowPackets.json')).preprocess_df()
    syn_flood_df = DataPreprocessor(DataLoader.transform_json_to_df('datasets/SYNFloodPacket.json')).preprocess_df()

    # Train-test split
    good_train_df, good_test_df = detector.split_training_testing_df(good_df)
    buffer_train_df, buffer_test_df = detector.split_training_testing_df(buffer_df)
    syn_flood_train_df, syn_flood_test_df = detector.split_training_testing_df(syn_flood_df)

    # Combine datasets
    train_df = pd.concat([good_train_df, buffer_train_df, syn_flood_train_df], ignore_index=True)
    train_df = train_df.dropna()
    test_df = pd.concat([good_test_df, buffer_test_df, syn_flood_test_df], ignore_index=True)

    # Train and predict using the model
    detector.load_and_train_model(train_df)
    test_results = detector.predict_model(test_df)


    # 6. Save the Model as a .pkl file
    joblib.dump(detector, "network_packet_classifier.pkl")
    print(test_results)
