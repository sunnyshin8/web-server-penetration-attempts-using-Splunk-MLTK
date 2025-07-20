import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import re
import warnings
warnings.filterwarnings('ignore')

class WebLogAnalyzer:
    """
    Advanced web log analyzer for detecting penetration attempts
    and suspicious behavior patterns in web server access logs.
    """
    
    def __init__(self, csv_file_path):
        """
        Initialize the analyzer with parsed CSV data.
        
        Args:
            csv_file_path (str): Path to the parsed CSV file
        """
        self.df = pd.read_csv(csv_file_path)
        self.prepare_data()
        
    def prepare_data(self):
        """Prepare and clean the data for analysis."""
        print("Preparing data for analysis...")
        
        # Convert datetime to proper datetime format
        self.df['datetime'] = pd.to_datetime(self.df['datetime'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce')
        
        # Extract useful features
        self.df['hour'] = self.df['datetime'].dt.hour
        self.df['day_of_week'] = self.df['datetime'].dt.day_name()
        self.df['status_code'] = pd.to_numeric(self.df['status'], errors='coerce')
        
        # Clean size column (handle '-' values)
        self.df['response_size'] = pd.to_numeric(self.df['size'].replace('-', '0'), errors='coerce')
        
        # Extract path components
        self.df['path_length'] = self.df['path'].str.len()
        self.df['path_depth'] = self.df['path'].str.count('/')
        
        # Flag suspicious patterns
        self.df['is_error'] = self.df['status_code'].between(400, 599)
        self.df['is_client_error'] = self.df['status_code'].between(400, 499)
        self.df['is_server_error'] = self.df['status_code'].between(500, 599)
        
        # Detect common attack patterns
        self.df['has_sql_injection'] = self.df['path'].str.contains(
            r'(?i)(union|select|insert|update|delete|drop|create|script|alert|javascript)',
            regex=True, na=False
        )
        
        self.df['has_directory_traversal'] = self.df['path'].str.contains(
            r'\.\./', regex=True, na=False
        )
        
        self.df['has_admin_access'] = self.df['path'].str.contains(
            r'(?i)(admin|wp-admin|phpmyadmin|login|dashboard)', regex=True, na=False
        )
        
        self.df['has_suspicious_extension'] = self.df['path'].str.contains(
            r'\.(?i)(php|asp|jsp|cgi|pl|py|sh|exe|bat)(\?|$)', regex=True, na=False
        )
        
        # User agent analysis
        self.df['is_bot'] = self.df['user_agent'].str.contains(
            r'(?i)(bot|crawler|spider|scraper|scanner)', regex=True, na=False
        )
        
        self.df['is_curl'] = self.df['user_agent'].str.contains(
            r'(?i)curl', regex=True, na=False
        )
        
        print(f"Data prepared successfully. Shape: {self.df.shape}")
        print(f"Date range: {self.df['datetime'].min()} to {self.df['datetime'].max()}")
        
    def detect_suspicious_ips(self, min_requests=50, error_threshold=0.3):
        """
        Detect suspicious IP addresses based on request patterns.
        
        Args:
            min_requests (int): Minimum number of requests to consider
            error_threshold (float): Minimum error rate to flag as suspicious
            
        Returns:
            pd.DataFrame: Suspicious IPs with statistics
        """
        print(f"Detecting suspicious IPs (min_requests={min_requests}, error_threshold={error_threshold})...")
        
        ip_stats = self.df.groupby('ip').agg({
            'datetime': ['count', 'min', 'max'],
            'is_error': 'sum',
            'is_client_error': 'sum',
            'is_server_error': 'sum',
            'has_sql_injection': 'sum',
            'has_directory_traversal': 'sum',
            'has_admin_access': 'sum',
            'path': 'nunique',
            'user_agent': 'nunique'
        }).round(3)
        
        # Flatten column names
        ip_stats.columns = ['total_requests', 'first_seen', 'last_seen', 'total_errors',
                           'client_errors', 'server_errors', 'sql_injection_attempts',
                           'directory_traversal_attempts', 'admin_access_attempts',
                           'unique_paths', 'unique_user_agents']
        
        # Calculate additional metrics
        ip_stats['error_rate'] = ip_stats['total_errors'] / ip_stats['total_requests']
        ip_stats['duration_hours'] = (ip_stats['last_seen'] - ip_stats['first_seen']).dt.total_seconds() / 3600
        ip_stats['requests_per_hour'] = ip_stats['total_requests'] / np.maximum(ip_stats['duration_hours'], 1)
        
        # Calculate suspicion score
        ip_stats['suspicion_score'] = (
            ip_stats['error_rate'] * 0.3 +
            np.minimum(ip_stats['requests_per_hour'] / 100, 1) * 0.2 +
            np.minimum(ip_stats['sql_injection_attempts'] / 10, 1) * 0.2 +
            np.minimum(ip_stats['directory_traversal_attempts'] / 10, 1) * 0.15 +
            np.minimum(ip_stats['admin_access_attempts'] / 20, 1) * 0.15
        )
        
        # Filter suspicious IPs
        suspicious_ips = ip_stats[
            (ip_stats['total_requests'] >= min_requests) &
            ((ip_stats['error_rate'] >= error_threshold) |
             (ip_stats['sql_injection_attempts'] > 0) |
             (ip_stats['directory_traversal_attempts'] > 0) |
             (ip_stats['requests_per_hour'] > 100))
        ].sort_values('suspicion_score', ascending=False)
        
        print(f"Found {len(suspicious_ips)} suspicious IPs")
        return suspicious_ips
    
    def analyze_attack_patterns(self):
        """Analyze common attack patterns in the logs."""
        print("Analyzing attack patterns...")
        
        patterns = {
            'SQL Injection': self.df['has_sql_injection'].sum(),
            'Directory Traversal': self.df['has_directory_traversal'].sum(),
            'Admin Access Attempts': self.df['has_admin_access'].sum(),
            'Suspicious Extensions': self.df['has_suspicious_extension'].sum(),
            'Client Errors (4xx)': self.df['is_client_error'].sum(),
            'Server Errors (5xx)': self.df['is_server_error'].sum(),
            'Bot Traffic': self.df['is_bot'].sum(),
            'Curl Requests': self.df['is_curl'].sum()
        }
        
        return patterns
    
    def detect_brute_force_attempts(self, time_window='1H', threshold=20):
        """
        Detect potential brute force attacks.
        
        Args:
            time_window (str): Time window for grouping requests
            threshold (int): Minimum requests in time window to flag
            
        Returns:
            pd.DataFrame: Potential brute force attempts
        """
        print(f"Detecting brute force attempts (window={time_window}, threshold={threshold})...")
        
        # Focus on authentication-related endpoints and errors
        auth_logs = self.df[
            (self.df['has_admin_access']) |
            (self.df['status_code'].isin([401, 403])) |
            (self.df['path'].str.contains(r'(?i)(login|auth|signin)', regex=True, na=False))
        ].copy()
        
        if auth_logs.empty:
            print("No authentication-related logs found")
            return pd.DataFrame()
        
        # Group by IP and time window
        auth_logs['time_bucket'] = auth_logs['datetime'].dt.floor(time_window)
        
        brute_force = auth_logs.groupby(['ip', 'time_bucket']).agg({
            'datetime': 'count',
            'status_code': lambda x: (x.isin([401, 403])).sum(),
            'path': lambda x: x.nunique()
        }).rename(columns={
            'datetime': 'total_requests',
            'status_code': 'failed_auth',
            'path': 'unique_paths'
        })
        
        # Filter potential brute force attempts
        brute_force = brute_force[brute_force['total_requests'] >= threshold]
        brute_force = brute_force.sort_values('total_requests', ascending=False)
        
        print(f"Found {len(brute_force)} potential brute force attempts")
        return brute_force
    
    def generate_report(self, output_file='security_analysis_report.txt'):
        """Generate a comprehensive security analysis report."""
        print("Generating security analysis report...")
        
        with open(output_file, 'w') as f:
            f.write("WEB SERVER SECURITY ANALYSIS REPORT\n")
            f.write("=" * 50 + "\n\n")
            
            # Basic statistics
            f.write("BASIC STATISTICS:\n")
            f.write(f"Total requests: {len(self.df):,}\n")
            f.write(f"Unique IPs: {self.df['ip'].nunique():,}\n")
            f.write(f"Date range: {self.df['datetime'].min()} to {self.df['datetime'].max()}\n")
            f.write(f"Total errors: {self.df['is_error'].sum():,} ({self.df['is_error'].mean()*100:.1f}%)\n\n")
            
            # Attack patterns
            f.write("ATTACK PATTERNS DETECTED:\n")
            patterns = self.analyze_attack_patterns()
            for pattern, count in patterns.items():
                f.write(f"{pattern}: {count:,}\n")
            f.write("\n")
            
            # Top suspicious IPs
            f.write("TOP 10 SUSPICIOUS IPs:\n")
            suspicious_ips = self.detect_suspicious_ips()
            if not suspicious_ips.empty:
                for ip, row in suspicious_ips.head(10).iterrows():
                    f.write(f"{ip}: {row['total_requests']} requests, "
                           f"{row['error_rate']:.1%} error rate, "
                           f"suspicion score: {row['suspicion_score']:.3f}\n")
            f.write("\n")
            
            # Brute force attempts
            f.write("BRUTE FORCE ATTEMPTS:\n")
            brute_force = self.detect_brute_force_attempts()
            if not brute_force.empty:
                f.write(f"Found {len(brute_force)} potential brute force attempts\n")
                for (ip, time_bucket), row in brute_force.head(10).iterrows():
                    f.write(f"{ip} at {time_bucket}: {row['total_requests']} requests, "
                           f"{row['failed_auth']} failed auth\n")
            else:
                f.write("No brute force attempts detected\n")
            f.write("\n")
            
            # Top error pages
            f.write("TOP ERROR PAGES:\n")
            error_pages = self.df[self.df['is_error']]['path'].value_counts().head(10)
            for path, count in error_pages.items():
                f.write(f"{path}: {count} errors\n")
            f.write("\n")
            
            # Recommendations
            f.write("SECURITY RECOMMENDATIONS:\n")
            f.write("1. Monitor and potentially block the suspicious IPs listed above\n")
            f.write("2. Implement rate limiting for authentication endpoints\n")
            f.write("3. Set up real-time alerts for SQL injection attempts\n")
            f.write("4. Review and secure admin access endpoints\n")
            f.write("5. Consider implementing a Web Application Firewall (WAF)\n")
            f.write("6. Regular security audits and penetration testing\n")
        
        print(f"Report saved to {output_file}")
    
    def create_visualizations(self):
        """Create security-focused visualizations."""
        print("Creating visualizations...")
        
        plt.style.use('default')
        fig, axes = plt.subplots(2, 3, figsize=(18, 12))
        fig.suptitle('Web Server Security Analysis Dashboard', fontsize=16)
        
        # 1. Requests over time
        hourly_requests = self.df.groupby(self.df['datetime'].dt.floor('H')).size()
        axes[0, 0].plot(hourly_requests.index, hourly_requests.values)
        axes[0, 0].set_title('Requests Over Time (Hourly)')
        axes[0, 0].tick_params(axis='x', rotation=45)
        
        # 2. Status code distribution
        status_counts = self.df['status_code'].value_counts().head(10)
        axes[0, 1].bar(status_counts.index.astype(str), status_counts.values)
        axes[0, 1].set_title('Top 10 HTTP Status Codes')
        axes[0, 1].tick_params(axis='x', rotation=45)
        
        # 3. Top IPs by request count
        top_ips = self.df['ip'].value_counts().head(10)
        axes[0, 2].barh(range(len(top_ips)), top_ips.values)
        axes[0, 2].set_yticks(range(len(top_ips)))
        axes[0, 2].set_yticklabels(top_ips.index)
        axes[0, 2].set_title('Top 10 IPs by Request Count')
        
        # 4. Error rate by hour
        hourly_errors = self.df.groupby('hour')['is_error'].mean()
        axes[1, 0].bar(hourly_errors.index, hourly_errors.values)
        axes[1, 0].set_title('Error Rate by Hour of Day')
        axes[1, 0].set_xlabel('Hour')
        axes[1, 0].set_ylabel('Error Rate')
        
        # 5. Attack patterns
        patterns = self.analyze_attack_patterns()
        attack_types = list(patterns.keys())
        attack_counts = list(patterns.values())
        axes[1, 1].pie(attack_counts, labels=attack_types, autopct='%1.1f%%')
        axes[1, 1].set_title('Attack Pattern Distribution')
        
        # 6. Path length distribution for suspicious requests
        suspicious_paths = self.df[
            self.df['has_sql_injection'] | 
            self.df['has_directory_traversal'] |
            self.df['has_admin_access']
        ]['path_length']
        
        if not suspicious_paths.empty:
            axes[1, 2].hist(suspicious_paths, bins=30, alpha=0.7)
            axes[1, 2].set_title('Path Length Distribution (Suspicious Requests)')
            axes[1, 2].set_xlabel('Path Length')
            axes[1, 2].set_ylabel('Frequency')
        else:
            axes[1, 2].text(0.5, 0.5, 'No suspicious\nrequests found', 
                           ha='center', va='center', transform=axes[1, 2].transAxes)
            axes[1, 2].set_title('Path Length Distribution (Suspicious Requests)')
        
        plt.tight_layout()
        plt.savefig('security_analysis_dashboard.png', dpi=300, bbox_inches='tight')
        print("Visualizations saved to security_analysis_dashboard.png")
        
        return fig

def main():
    """Main function to run the security analysis."""
    print("Starting Web Server Security Analysis...")
    
    # Initialize analyzer
    analyzer = WebLogAnalyzer('access_parsed.csv')
    
    # Perform analysis
    print("\n" + "="*50)
    print("SUSPICIOUS IP DETECTION")
    print("="*50)
    suspicious_ips = analyzer.detect_suspicious_ips()
    if not suspicious_ips.empty:
        print(suspicious_ips.head())
    
    print("\n" + "="*50)
    print("ATTACK PATTERN ANALYSIS")
    print("="*50)
    patterns = analyzer.analyze_attack_patterns()
    for pattern, count in patterns.items():
        print(f"{pattern}: {count:,}")
    
    print("\n" + "="*50)
    print("BRUTE FORCE DETECTION")
    print("="*50)
    brute_force = analyzer.detect_brute_force_attempts()
    if not brute_force.empty:
        print(brute_force.head())
    
    # Generate comprehensive report
    analyzer.generate_report()
    
    # Create visualizations
    analyzer.create_visualizations()
    
    print("\nAnalysis complete! Check the generated files:")
    print("- security_analysis_report.txt")
    print("- security_analysis_dashboard.png")

if __name__ == "__main__":
    main()
