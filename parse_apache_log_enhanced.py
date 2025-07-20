# Enhanced Apache Log Parser with Additional Security Features

import re
import csv
import sys
from datetime import datetime
import argparse
from pathlib import Path

class EnhancedApacheLogParser:
    """
    Enhanced Apache log parser with additional security-focused field extraction
    and data enrichment capabilities.
    """
    
    def __init__(self, log_format='combined'):
        """
        Initialize the parser with specified log format.
        
        Args:
            log_format (str): Log format type ('combined', 'common', 'custom')
        """
        self.log_format = log_format
        self.patterns = self._get_patterns()
        self.security_patterns = self._get_security_patterns()
        
    def _get_patterns(self):
        """Define regex patterns for different Apache log formats."""
        patterns = {
            'combined': re.compile(
                r'(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<datetime>[^\]]+)\] '
                r'"(?P<method>\S+)? (?P<path>\S+)? (?P<protocol>\S+?)?" '
                r'(?P<status>\d{3}) (?P<size>\d+|-) '
                r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
            ),
            'common': re.compile(
                r'(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<datetime>[^\]]+)\] '
                r'"(?P<method>\S+)? (?P<path>\S+)? (?P<protocol>\S+?)?" '
                r'(?P<status>\d{3}) (?P<size>\d+|-)'
            ),
            'custom_with_time': re.compile(
                r'(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<datetime>[^\]]+)\] '
                r'"(?P<method>\S+)? (?P<path>\S+)? (?P<protocol>\S+?)?" '
                r'(?P<status>\d{3}) (?P<size>\d+|-) '
                r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)" (?P<response_time>\d+)'
            )
        }
        return patterns
    
    def _get_security_patterns(self):
        """Define security-focused regex patterns for threat detection."""
        return {
            'sql_injection': re.compile(
                r'(?i)(union(\s+(all|distinct))?(\s+select)|select.+(from|limit)|'
                r'insert(\s+into)?|update(\s+\w+)?(\s+set)|delete(\s+from)?|'
                r'drop(\s+(table|database))|create(\s+(table|database))|'
                r'exec(\s*\()|sp_|xp_|script|alert)'
            ),
            'xss': re.compile(
                r'(?i)(<script|javascript:|on\w+\s*=|<iframe|<object|<embed|'
                r'<link|<meta|<style|<img[^>]+src\s*=\s*["\']?javascript)'
            ),
            'directory_traversal': re.compile(
                r'(\.\./|\.\.%2f|\.\.%5c|%2e%2e%2f|%2e%2e%5c|\.\./)'
            ),
            'command_injection': re.compile(
                r'(?i)(;|\||&|`|\$\(|%0a|%0d|%3b|%7c|%26|%60|\x00)'
                r'(\s*)(cat|ls|dir|type|echo|ping|nc|netcat|wget|curl|python|'
                r'perl|ruby|php|bash|sh|cmd|powershell)'
            ),
            'admin_access': re.compile(
                r'(?i)(admin|administrator|wp-admin|phpmyadmin|cpanel|webmail|'
                r'manager|console|dashboard|control|panel)'
            ),
            'suspicious_files': re.compile(
                r'(?i)\.(php|asp|aspx|jsp|cgi|pl|py|sh|exe|bat|cmd|scr|vbs|js|jar|war|cfm)'
                r'(\?.*)?$'
            ),
            'brute_force_paths': re.compile(
                r'(?i)(login|signin|auth|authenticate|logon|session|password|pwd|pass|credential)'
            ),
            'bot_indicators': re.compile(
                r'(?i)(bot|crawler|spider|scraper|scanner|curl|wget|python-requests|'
                r'automated|headless)'
            )
        }
    
    def parse_line(self, line):
        """
        Parse a single log line and extract all fields.
        
        Args:
            line (str): Raw log line
            
        Returns:
            dict: Parsed fields or None if parsing fails
        """
        pattern = self.patterns.get(self.log_format)
        if not pattern:
            raise ValueError(f"Unsupported log format: {self.log_format}")
        
        match = pattern.match(line.strip())
        if not match:
            return None
        
        # Extract basic fields
        data = match.groupdict()
        
        # Add security analysis fields
        data.update(self._analyze_security_indicators(data))
        
        # Add derived fields
        data.update(self._extract_derived_fields(data))
        
        return data
    
    def _analyze_security_indicators(self, data):
        """
        Analyze the request for security indicators.
        
        Args:
            data (dict): Parsed log data
            
        Returns:
            dict: Security indicator flags
        """
        path = data.get('path', '')
        user_agent = data.get('user_agent', '')
        
        indicators = {}
        
        # Check for attack patterns
        for pattern_name, pattern in self.security_patterns.items():
            if pattern_name in ['bot_indicators']:
                indicators[f'has_{pattern_name}'] = bool(pattern.search(user_agent))
            else:
                indicators[f'has_{pattern_name}'] = bool(pattern.search(path))
        
        return indicators
    
    def _extract_derived_fields(self, data):
        """
        Extract additional derived fields for analysis.
        
        Args:
            data (dict): Parsed log data
            
        Returns:
            dict: Derived fields
        """
        derived = {}
        
        # Path analysis
        path = data.get('path', '')
        derived['path_length'] = len(path)
        derived['path_depth'] = path.count('/')
        derived['has_query_params'] = '?' in path
        derived['query_param_count'] = path.count('&') if '?' in path else 0
        
        # Status code analysis
        status = data.get('status', '200')
        try:
            status_code = int(status)
            derived['status_category'] = self._categorize_status(status_code)
            derived['is_error'] = status_code >= 400
            derived['is_client_error'] = 400 <= status_code < 500
            derived['is_server_error'] = status_code >= 500
        except (ValueError, TypeError):
            derived['status_category'] = 'unknown'
            derived['is_error'] = False
            derived['is_client_error'] = False
            derived['is_server_error'] = False
        
        # Size analysis
        size = data.get('size', '0')
        try:
            derived['response_size'] = int(size) if size != '-' else 0
            derived['has_response_body'] = derived['response_size'] > 0
        except (ValueError, TypeError):
            derived['response_size'] = 0
            derived['has_response_body'] = False
        
        # User agent analysis
        user_agent = data.get('user_agent', '')
        derived['user_agent_length'] = len(user_agent)
        derived['is_empty_user_agent'] = len(user_agent.strip()) == 0
        derived['is_short_user_agent'] = len(user_agent) < 20
        derived['is_long_user_agent'] = len(user_agent) > 500
        
        # Time analysis
        try:
            dt = datetime.strptime(data.get('datetime', ''), '%d/%b/%Y:%H:%M:%S %z')
            derived['hour'] = dt.hour
            derived['day_of_week'] = dt.strftime('%A')
            derived['is_weekend'] = dt.weekday() >= 5
            derived['is_business_hours'] = 9 <= dt.hour <= 17
        except (ValueError, TypeError):
            derived['hour'] = None
            derived['day_of_week'] = None
            derived['is_weekend'] = None
            derived['is_business_hours'] = None
        
        return derived
    
    def _categorize_status(self, status_code):
        """Categorize HTTP status codes."""
        if 200 <= status_code < 300:
            return 'success'
        elif 300 <= status_code < 400:
            return 'redirection'
        elif 400 <= status_code < 500:
            return 'client_error'
        elif 500 <= status_code < 600:
            return 'server_error'
        else:
            return 'unknown'
    
    def get_csv_headers(self):
        """Get CSV headers for the enhanced parser."""
        base_headers = [
            'ip', 'ident', 'user', 'datetime', 'method', 'path', 'protocol', 
            'status', 'size', 'referrer', 'user_agent'
        ]
        
        # Add response_time if using custom format
        if self.log_format == 'custom_with_time':
            base_headers.append('response_time')
        
        # Security indicators
        security_headers = [
            'has_sql_injection', 'has_xss', 'has_directory_traversal',
            'has_command_injection', 'has_admin_access', 'has_suspicious_files',
            'has_brute_force_paths', 'has_bot_indicators'
        ]
        
        # Derived fields
        derived_headers = [
            'path_length', 'path_depth', 'has_query_params', 'query_param_count',
            'status_category', 'is_error', 'is_client_error', 'is_server_error',
            'response_size', 'has_response_body', 'user_agent_length',
            'is_empty_user_agent', 'is_short_user_agent', 'is_long_user_agent',
            'hour', 'day_of_week', 'is_weekend', 'is_business_hours'
        ]
        
        return base_headers + security_headers + derived_headers

def main():
    """Main function to parse Apache logs with command line interface."""
    parser = argparse.ArgumentParser(
        description='Enhanced Apache Log Parser with Security Analysis'
    )
    parser.add_argument('input_file', help='Input Apache log file')
    parser.add_argument('-o', '--output', default='access_parsed_enhanced.csv',
                       help='Output CSV file (default: access_parsed_enhanced.csv)')
    parser.add_argument('-f', '--format', choices=['combined', 'common', 'custom_with_time'],
                       default='combined', help='Apache log format (default: combined)')
    parser.add_argument('--stats', action='store_true',
                       help='Show parsing statistics')
    
    args = parser.parse_args()
    
    # Initialize parser
    log_parser = EnhancedApacheLogParser(log_format=args.format)
    
    # Check if input file exists
    input_path = Path(args.input_file)
    if not input_path.exists():
        print(f"Error: Input file '{args.input_file}' not found.")
        sys.exit(1)
    
    # Parse logs
    print(f"Parsing {args.input_file} with format '{args.format}'...")
    
    total_lines = 0
    parsed_lines = 0
    error_lines = 0
    
    with open(input_path, 'r', encoding='utf-8', errors='ignore') as infile, \
         open(args.output, 'w', newline='', encoding='utf-8') as outfile:
        
        writer = csv.DictWriter(outfile, fieldnames=log_parser.get_csv_headers())
        writer.writeheader()
        
        for line_num, line in enumerate(infile, 1):
            total_lines += 1
            
            if line_num % 10000 == 0:
                print(f"Processed {line_num:,} lines...")
            
            try:
                parsed_data = log_parser.parse_line(line)
                if parsed_data:
                    writer.writerow(parsed_data)
                    parsed_lines += 1
                else:
                    error_lines += 1
                    if args.stats and error_lines <= 5:  # Show first 5 errors
                        print(f"Failed to parse line {line_num}: {line.strip()}")
            except Exception as e:
                error_lines += 1
                if args.stats and error_lines <= 5:
                    print(f"Error on line {line_num}: {e}")
    
    # Print statistics
    success_rate = (parsed_lines / total_lines * 100) if total_lines > 0 else 0
    
    print(f"\nParsing Complete!")
    print(f"Total lines processed: {total_lines:,}")
    print(f"Successfully parsed: {parsed_lines:,}")
    print(f"Failed to parse: {error_lines:,}")
    print(f"Success rate: {success_rate:.2f}%")
    print(f"Output saved to: {args.output}")
    
    if args.stats and parsed_lines > 0:
        print(f"\nGenerating quick statistics...")
        
        # Quick analysis of parsed data
        import pandas as pd
        try:
            df = pd.read_csv(args.output)
            
            print(f"\nQuick Security Analysis:")
            print(f"SQL Injection attempts: {df['has_sql_injection'].sum():,}")
            print(f"XSS attempts: {df['has_xss'].sum():,}")
            print(f"Directory traversal attempts: {df['has_directory_traversal'].sum():,}")
            print(f"Admin access attempts: {df['has_admin_access'].sum():,}")
            print(f"Bot traffic: {df['has_bot_indicators'].sum():,}")
            print(f"Error responses (4xx/5xx): {df['is_error'].sum():,}")
            
            print(f"\nTop 5 IP addresses by request count:")
            top_ips = df['ip'].value_counts().head()
            for ip, count in top_ips.items():
                print(f"  {ip}: {count:,} requests")
                
        except ImportError:
            print("Install pandas for detailed statistics: pip install pandas")
        except Exception as e:
            print(f"Error generating statistics: {e}")

if __name__ == "__main__":
    main()
