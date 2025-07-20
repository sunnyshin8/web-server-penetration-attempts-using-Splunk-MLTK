

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.decomposition import PCA
from sklearn.model_selection import train_test_split
import joblib
import json
from datetime import datetime, timedelta

class SecurityMLModels:
    """
    Machine Learning models for detecting web server penetration attempts.
    This class implements various unsupervised learning algorithms suitable for anomaly detection.
    """
    
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.feature_columns = []
        self.label_encoders = {}
        
    def prepare_features(self, df):
        """
        Prepare features for machine learning models.
        
        Args:
            df (pd.DataFrame): Web log data
            
        Returns:
            pd.DataFrame: Processed features
        """
        print("Preparing features for ML models...")
        
        # Create a copy for feature engineering
        features_df = df.copy()
        
        # Time-based features
        features_df['hour'] = pd.to_datetime(features_df['datetime']).dt.hour
        features_df['day_of_week'] = pd.to_datetime(features_df['datetime']).dt.dayofweek
        features_df['is_weekend'] = features_df['day_of_week'].isin([5, 6]).astype(int)
        
        # Request characteristics
        features_df['path_length'] = features_df['path'].str.len()
        features_df['path_depth'] = features_df['path'].str.count('/')
        features_df['has_query_params'] = features_df['path'].str.contains('\\?').astype(int)
        features_df['query_param_count'] = features_df['path'].str.count('&') + features_df['has_query_params']
        
        # Status code categories
        features_df['status_code'] = pd.to_numeric(features_df['status'], errors='coerce')
        features_df['is_success'] = (features_df['status_code'] < 400).astype(int)
        features_df['is_client_error'] = ((features_df['status_code'] >= 400) & (features_df['status_code'] < 500)).astype(int)
        features_df['is_server_error'] = (features_df['status_code'] >= 500).astype(int)
        
        # Response size
        features_df['response_size'] = pd.to_numeric(features_df['size'].replace('-', '0'), errors='coerce')
        features_df['has_response_body'] = (features_df['response_size'] > 0).astype(int)
        
        # User agent features
        features_df['ua_length'] = features_df['user_agent'].str.len()
        features_df['is_bot'] = features_df['user_agent'].str.contains(
            r'(?i)(bot|crawler|spider|scraper|scanner)', regex=True, na=False
        ).astype(int)
        features_df['is_curl'] = features_df['user_agent'].str.contains(
            r'(?i)curl', regex=True, na=False
        ).astype(int)
        
        # HTTP method encoding
        if 'method' not in self.label_encoders:
            self.label_encoders['method'] = LabelEncoder()
            features_df['method_encoded'] = self.label_encoders['method'].fit_transform(features_df['method'].fillna('GET'))
        else:
            features_df['method_encoded'] = self.label_encoders['method'].transform(features_df['method'].fillna('GET'))
        
        # Suspicious pattern flags
        features_df['has_sql_injection'] = features_df['path'].str.contains(
            r'(?i)(union|select|insert|update|delete|drop|create|script|alert)', regex=True, na=False
        ).astype(int)
        
        features_df['has_directory_traversal'] = features_df['path'].str.contains(
            r'\.\./', regex=True, na=False
        ).astype(int)
        
        features_df['has_admin_access'] = features_df['path'].str.contains(
            r'(?i)(admin|wp-admin|phpmyadmin|login|dashboard)', regex=True, na=False
        ).astype(int)
        
        features_df['has_suspicious_extension'] = features_df['path'].str.contains(
            r'\.(?i)(php|asp|jsp|cgi|pl|py|sh|exe|bat)(\?|$)', regex=True, na=False
        ).astype(int)
        
        features_df['has_special_chars'] = features_df['path'].str.contains(
            r'[<>"\';()&+%]', regex=True, na=False
        ).astype(int)
        
        # IP-based features (aggregate features)
        ip_stats = features_df.groupby('ip').agg({
            'datetime': 'count',
            'is_client_error': 'sum',
            'is_server_error': 'sum',
            'path': 'nunique',
            'user_agent': 'nunique'
        }).rename(columns={
            'datetime': 'ip_request_count',
            'is_client_error': 'ip_client_errors',
            'is_server_error': 'ip_server_errors',
            'path': 'ip_unique_paths',
            'user_agent': 'ip_unique_agents'
        })
        
        ip_stats['ip_error_rate'] = (ip_stats['ip_client_errors'] + ip_stats['ip_server_errors']) / ip_stats['ip_request_count']
        
        # Merge IP stats back to features
        features_df = features_df.merge(ip_stats, left_on='ip', right_index=True, how='left')
        
        # Select numerical features for ML
        self.feature_columns = [
            'hour', 'day_of_week', 'is_weekend',
            'path_length', 'path_depth', 'has_query_params', 'query_param_count',
            'status_code', 'is_success', 'is_client_error', 'is_server_error',
            'response_size', 'has_response_body',
            'ua_length', 'is_bot', 'is_curl', 'method_encoded',
            'has_sql_injection', 'has_directory_traversal', 'has_admin_access',
            'has_suspicious_extension', 'has_special_chars',
            'ip_request_count', 'ip_client_errors', 'ip_server_errors',
            'ip_unique_paths', 'ip_unique_agents', 'ip_error_rate'
        ]
        
        # Fill missing values
        for col in self.feature_columns:
            if col in features_df.columns:
                features_df[col] = features_df[col].fillna(0)
        
        print(f"Prepared {len(self.feature_columns)} features for ML models")
        return features_df[self.feature_columns + ['ip', 'path', 'datetime']]
    
    def train_isolation_forest(self, features_df, contamination=0.1, model_name='isolation_forest'):
        """
        Train Isolation Forest for anomaly detection.
        
        Args:
            features_df (pd.DataFrame): Prepared features
            contamination (float): Expected proportion of anomalies
            model_name (str): Name for the model
        """
        print(f"Training Isolation Forest model: {model_name}")
        
        # Prepare data
        X = features_df[self.feature_columns].values
        
        # Scale features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        self.scalers[model_name] = scaler
        
        # Train model
        model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100,
            max_samples='auto',
            max_features=1.0,
            bootstrap=False
        )
        
        model.fit(X_scaled)
        self.models[model_name] = model
        
        # Get predictions
        predictions = model.predict(X_scaled)
        scores = model.decision_function(X_scaled)
        
        # Add results to dataframe
        features_df[f'{model_name}_prediction'] = predictions
        features_df[f'{model_name}_score'] = scores
        features_df[f'{model_name}_anomaly'] = (predictions == -1).astype(int)
        
        anomaly_count = (predictions == -1).sum()
        print(f"Isolation Forest detected {anomaly_count} anomalies ({anomaly_count/len(features_df)*100:.2f}%)")
        
        return features_df
    
    def train_dbscan_clustering(self, features_df, eps=0.5, min_samples=5, model_name='dbscan'):
        """
        Train DBSCAN clustering for anomaly detection.
        
        Args:
            features_df (pd.DataFrame): Prepared features
            eps (float): Maximum distance between samples
            min_samples (int): Minimum samples in cluster
            model_name (str): Name for the model
        """
        print(f"Training DBSCAN clustering model: {model_name}")
        
        # Prepare data
        X = features_df[self.feature_columns].values
        
        # Scale features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        self.scalers[model_name] = scaler
        
        # Apply PCA for dimensionality reduction
        pca = PCA(n_components=0.95)  # Keep 95% variance
        X_pca = pca.fit_transform(X_scaled)
        
        # Train DBSCAN
        model = DBSCAN(eps=eps, min_samples=min_samples, metric='euclidean')
        cluster_labels = model.fit_predict(X_pca)
        
        self.models[model_name] = {'dbscan': model, 'pca': pca}
        
        # Add results to dataframe
        features_df[f'{model_name}_cluster'] = cluster_labels
        features_df[f'{model_name}_anomaly'] = (cluster_labels == -1).astype(int)
        
        n_clusters = len(set(cluster_labels)) - (1 if -1 in cluster_labels else 0)
        n_noise = list(cluster_labels).count(-1)
        
        print(f"DBSCAN found {n_clusters} clusters and {n_noise} noise points ({n_noise/len(features_df)*100:.2f}%)")
        
        return features_df
    
    def train_request_frequency_model(self, df, time_window='1H', model_name='frequency_anomaly'):
        """
        Train model to detect request frequency anomalies.
        
        Args:
            df (pd.DataFrame): Original dataframe with datetime
            time_window (str): Time window for aggregation
            model_name (str): Name for the model
        """
        print(f"Training request frequency anomaly model: {model_name}")
        
        # Convert datetime and create time buckets
        df['datetime'] = pd.to_datetime(df['datetime'])
        df['time_bucket'] = df['datetime'].dt.floor(time_window)
        
        # Aggregate by IP and time bucket
        freq_features = df.groupby(['ip', 'time_bucket']).agg({
            'datetime': 'count',
            'status': lambda x: (pd.to_numeric(x, errors='coerce') >= 400).sum(),
            'path': 'nunique',
            'user_agent': 'nunique'
        }).rename(columns={
            'datetime': 'request_count',
            'status': 'error_count',
            'path': 'unique_paths',
            'user_agent': 'unique_agents'
        }).reset_index()
        
        freq_features['error_rate'] = freq_features['error_count'] / freq_features['request_count']
        
        # Prepare features for anomaly detection
        feature_cols = ['request_count', 'error_count', 'unique_paths', 'unique_agents', 'error_rate']
        X = freq_features[feature_cols].fillna(0).values
        
        # Scale and train
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        self.scalers[model_name] = scaler
        
        model = IsolationForest(contamination=0.05, random_state=42)
        model.fit(X_scaled)
        self.models[model_name] = model
        
        # Get predictions
        predictions = model.predict(X_scaled)
        freq_features[f'{model_name}_anomaly'] = (predictions == -1).astype(int)
        
        anomaly_count = (predictions == -1).sum()
        print(f"Frequency model detected {anomaly_count} anomalous time periods")
        
        return freq_features
    
    def predict_anomalies(self, features_df, model_name):
        """
        Use trained model to predict anomalies on new data.
        
        Args:
            features_df (pd.DataFrame): New data features
            model_name (str): Name of the trained model
            
        Returns:
            pd.DataFrame: Data with anomaly predictions
        """
        if model_name not in self.models:
            raise ValueError(f"Model {model_name} not found. Train the model first.")
        
        X = features_df[self.feature_columns].fillna(0).values
        X_scaled = self.scalers[model_name].transform(X)
        
        if model_name == 'dbscan':
            # For DBSCAN, use distance to existing clusters
            pca = self.models[model_name]['pca']
            X_pca = pca.transform(X_scaled)
            # Simplified prediction - in practice, you'd implement proper cluster distance calculation
            predictions = np.ones(len(X_pca))  # Placeholder
        else:
            predictions = self.models[model_name].predict(X_scaled)
            
        features_df[f'{model_name}_prediction'] = predictions
        features_df[f'{model_name}_anomaly'] = (predictions == -1).astype(int)
        
        return features_df
    
    def save_models(self, filepath_prefix='models/security_ml'):
        """
        Save trained models and scalers to disk.
        
        Args:
            filepath_prefix (str): Prefix for model files
        """
        print(f"Saving models to {filepath_prefix}...")
        
        # Save models
        for name, model in self.models.items():
            joblib.dump(model, f"{filepath_prefix}_{name}_model.pkl")
        
        # Save scalers
        for name, scaler in self.scalers.items():
            joblib.dump(scaler, f"{filepath_prefix}_{name}_scaler.pkl")
        
        # Save label encoders
        for name, encoder in self.label_encoders.items():
            joblib.dump(encoder, f"{filepath_prefix}_{name}_encoder.pkl")
        
        # Save feature columns
        with open(f"{filepath_prefix}_features.json", 'w') as f:
            json.dump(self.feature_columns, f)
        
        print("Models saved successfully")
    
    def load_models(self, filepath_prefix='models/security_ml'):
        """
        Load trained models and scalers from disk.
        
        Args:
            filepath_prefix (str): Prefix for model files
        """
        print(f"Loading models from {filepath_prefix}...")
        
        import os
        import glob
        
        # Load models
        model_files = glob.glob(f"{filepath_prefix}_*_model.pkl")
        for filepath in model_files:
            name = os.path.basename(filepath).replace(f"{os.path.basename(filepath_prefix)}_", "").replace("_model.pkl", "")
            self.models[name] = joblib.load(filepath)
        
        # Load scalers
        scaler_files = glob.glob(f"{filepath_prefix}_*_scaler.pkl")
        for filepath in scaler_files:
            name = os.path.basename(filepath).replace(f"{os.path.basename(filepath_prefix)}_", "").replace("_scaler.pkl", "")
            self.scalers[name] = joblib.load(filepath)
        
        # Load label encoders
        encoder_files = glob.glob(f"{filepath_prefix}_*_encoder.pkl")
        for filepath in encoder_files:
            name = os.path.basename(filepath).replace(f"{os.path.basename(filepath_prefix)}_", "").replace("_encoder.pkl", "")
            self.label_encoders[name] = joblib.load(filepath)
        
        # Load feature columns
        try:
            with open(f"{filepath_prefix}_features.json", 'r') as f:
                self.feature_columns = json.load(f)
        except FileNotFoundError:
            print("Feature columns file not found")
        
        print(f"Loaded {len(self.models)} models and {len(self.scalers)} scalers")

def main():
    """Main function to train ML models on web log data."""
    print("Starting ML model training for web server security...")
    
    # Load data
    df = pd.read_csv('access_parsed.csv')
    print(f"Loaded {len(df)} log entries")
    
    # Initialize ML models
    ml_models = SecurityMLModels()
    
    # Prepare features
    features_df = ml_models.prepare_features(df)
    
    # Train models
    print("\n" + "="*50)
    print("TRAINING ANOMALY DETECTION MODELS")
    print("="*50)
    
    # 1. Train Isolation Forest for general anomaly detection
    features_df = ml_models.train_isolation_forest(features_df, contamination=0.05, model_name='general_anomaly')
    
    # 2. Train DBSCAN for clustering-based anomaly detection
    features_df = ml_models.train_dbscan_clustering(features_df, eps=0.3, min_samples=10, model_name='cluster_anomaly')
    
    # 3. Train request frequency anomaly detection
    freq_anomalies = ml_models.train_request_frequency_model(df, time_window='1H', model_name='frequency_anomaly')
    
    # 4. Train specialized model for attack patterns
    attack_features = features_df[
        (features_df['has_sql_injection'] == 1) |
        (features_df['has_directory_traversal'] == 1) |
        (features_df['has_admin_access'] == 1) |
        (features_df['is_client_error'] == 1)
    ]
    
    if len(attack_features) > 100:
        attack_features = ml_models.train_isolation_forest(
            attack_features, contamination=0.1, model_name='attack_pattern'
        )
    
    # Save models
    ml_models.save_models('ml_models/security_ml')
    
    # Generate anomaly report
    print("\n" + "="*50)
    print("ANOMALY DETECTION RESULTS")
    print("="*50)
    
    for model_name in ['general_anomaly', 'cluster_anomaly']:
        if f'{model_name}_anomaly' in features_df.columns:
            anomalies = features_df[features_df[f'{model_name}_anomaly'] == 1]
            print(f"\n{model_name.upper()} MODEL:")
            print(f"Detected {len(anomalies)} anomalies ({len(anomalies)/len(features_df)*100:.2f}%)")
            
            if len(anomalies) > 0:
                print("Top anomalous IPs:")
                top_anomalous_ips = anomalies['ip'].value_counts().head(5)
                for ip, count in top_anomalous_ips.items():
                    print(f"  {ip}: {count} anomalous requests")
    
    # Save detailed anomaly results
    anomaly_results = features_df[
        (features_df.get('general_anomaly_anomaly', 0) == 1) |
        (features_df.get('cluster_anomaly_anomaly', 0) == 1)
    ][['ip', 'path', 'datetime'] + [col for col in features_df.columns if 'anomaly' in col]]
    
    anomaly_results.to_csv('ml_models/detected_anomalies.csv', index=False)
    print(f"\nDetailed anomaly results saved to ml_models/detected_anomalies.csv")
    
    print("\nML model training completed successfully!")

if __name__ == "__main__":
    main()
