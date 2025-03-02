# Importing necessary libraries
import pandas as pd
import json
import numpy as np
from ipaddress import ip_address
from sklearn.ensemble import IsolationForest

class DataLoader:
    @staticmethod
    def transform_json_to_df(json_path):
        with open(json_path, "r") as file:
            data = json.load(file)
        return pd.json_normalize(data)

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
    
    def predict(self, test_df):
        test_df = test_df.copy()
        if "Time" in test_df.columns:
            test_df["Time"] = (test_df["Time"] - test_df["Time"].min()).dt.total_seconds()
        test_df["anomaly_score"] = self.model.predict(test_df.drop(columns=["Time"], errors='ignore'))
        return test_df[['Time', 'anomaly_score']]

def split_training_testing_df(df):
    split_time = df["Time"].quantile(0.8)
    train_df = df[df["Time"] <= split_time]
    test_df = df[df["Time"] > split_time]
    return train_df, test_df

# Load and preprocess data
good_df = DataPreprocessor(DataLoader.transform_json_to_df('/content/goodPackets.json')).preprocess_df()
buffer_df = DataPreprocessor(DataLoader.transform_json_to_df('/content/BufferOverflowPackets.json')).preprocess_df()
syn_flood_df = DataPreprocessor(DataLoader.transform_json_to_df('/content/SYNFloodPacket.json')).preprocess_df()

# Train-test split
good_train_df, good_test_df = split_training_testing_df(good_df)
buffer_train_df, buffer_test_df = split_training_testing_df(buffer_df)
syn_flood_train_df, syn_flood_test_df = split_training_testing_df(syn_flood_df)

# Combine datasets
train_df = pd.concat([good_train_df, buffer_train_df, syn_flood_train_df], ignore_index=True)
test_df = pd.concat([good_test_df, buffer_test_df, syn_flood_test_df], ignore_index=True)

# Train and predict using the model
detector = AnomalyDetector()
detector.load_and_train_model(train_df)
test_results = detector.predict(test_df)

print(test_results['anomaly_score'].value_counts())
