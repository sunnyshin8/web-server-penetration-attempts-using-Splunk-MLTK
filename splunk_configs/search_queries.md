# Splunk Search Queries for Web Server Penetration Detection

## 1. BASIC THREAT DETECTION SEARCHES

### SQL Injection Detection
```spl
index=webserver sourcetype=access_combined OR sourcetype=csv_access_logs
| regex uri_path="(?i)(union|select|insert|update|delete|drop|create|script|alert|javascript)"
| eval attack_type="SQL Injection"
| stats count by src_ip, uri_path, attack_type, http_user_agent
| where count > 1
| sort -count
```

### Directory Traversal Detection
```spl
index=webserver sourcetype=access_combined OR sourcetype=csv_access_logs
| regex uri_path="(\.\./|\.\.%2f|\.\.%5c|%2e%2e%2f|%2e%2e%5c)"
| eval attack_type="Directory Traversal"
| stats count by src_ip, uri_path, attack_type
| sort -count
```

### Brute Force Detection
```spl
index=webserver sourcetype=access_combined OR sourcetype=csv_access_logs
| where status IN ("401", "403") OR match(uri_path, "(?i)(login|signin|auth)")
| bucket _time span=5m
| stats count by _time, src_ip
| where count > 10
| sort -count
```

### Admin Access Attempts
```spl
index=webserver sourcetype=access_combined OR sourcetype=csv_access_logs
| regex uri_path="(?i)(admin|wp-admin|phpmyadmin|cpanel|webmail|manager|console|dashboard)"
| eval attack_type="Admin Access Attempt"
| stats count by src_ip, uri_path, status, attack_type
| sort -count
```

## 2. ANOMALY DETECTION WITH MLTK

### Request Volume Anomaly Detection
```spl
index=webserver sourcetype=access_combined OR sourcetype=csv_access_logs
| bucket _time span=1h
| stats count as request_count by _time, src_ip
| fit IsolationForest request_count into request_volume_model
| where outlier="True"
| sort -request_count
```

### Path Length Anomaly Detection
```spl
index=webserver sourcetype=access_combined OR sourcetype=csv_access_logs
| eval path_length=len(uri_path)
| where path_length > 50
| fit DBSCAN path_length eps=10 minpts=5 into path_anomaly_model
| where cluster=-1
| stats count by src_ip, uri_path, path_length
| sort -path_length
```

### User Agent Anomaly Detection
```spl
index=webserver sourcetype=access_combined OR sourcetype=csv_access_logs
| stats count by http_user_agent, src_ip
| fit IsolationForest count into useragent_anomaly_model
| where outlier="True"
| sort -count
```

### Response Time Anomaly Detection
```spl
index=webserver sourcetype=access_combined OR sourcetype=csv_access_logs
| bucket _time span=10m
| stats avg(response_time) as avg_response_time by _time, uri_path
| fit IsolationForest avg_response_time into response_time_model
| where outlier="True"
```

## 3. BEHAVIOR PATTERN ANALYSIS

### IP Reputation Analysis
```spl
index=webserver sourcetype=access_combined OR sourcetype=csv_access_logs
| stats count, dc(uri_path) as unique_paths, dc(http_user_agent) as unique_agents, 
        sum(eval(if(status>=400,1,0))) as error_count by src_ip
| eval error_rate=round(error_count/count*100,2)
| where count > 50 AND (error_rate > 30 OR unique_paths > 100 OR unique_agents > 10)
| lookup geoip_lookup client_ip as src_ip OUTPUT country, region, city
| sort -count
```

### Scanning Behavior Detection
```spl
index=webserver sourcetype=access_combined OR sourcetype=csv_access_logs
| where status=404
| stats count, values(uri_path) as attempted_paths by src_ip
| where count > 20
| eval scanning_score = count * mvcount(attempted_paths)
| sort -scanning_score
```

### Bot Traffic Analysis
```spl
index=webserver sourcetype=access_combined OR sourcetype=csv_access_logs
| regex http_user_agent="(?i)(bot|crawler|spider|scraper|scanner)"
| stats count, dc(uri_path) as unique_paths, dc(status) as unique_statuses by src_ip, http_user_agent
| where count > 100
| sort -count
```

## 4. REAL-TIME ALERTING SEARCHES

### High-Frequency Attack Detection (Real-time)
```spl
index=webserver sourcetype=access_combined OR sourcetype=csv_access_logs
| eval attack_indicator=case(
    match(uri_path, "(?i)(union|select|insert|update|delete)"), "SQL_INJECTION",
    match(uri_path, "(\.\./|\.\.%2f)"), "DIRECTORY_TRAVERSAL",
    match(uri_path, "(?i)(admin|wp-admin|phpmyadmin)"), "ADMIN_ACCESS",
    status IN ("401","403") AND match(uri_path, "(?i)(login|auth)"), "BRUTE_FORCE",
    1=1, "NORMAL"
)
| where attack_indicator != "NORMAL"
| bucket _time span=1m
| stats count by _time, src_ip, attack_indicator
| where count >= 5
```

### Critical Vulnerability Exploitation
```spl
index=webserver sourcetype=access_combined OR sourcetype=csv_access_logs
| regex uri_path="(?i)(wp-config|\.env|backup|database|passwd|shadow|etc/passwd)"
| eval severity="CRITICAL"
| stats count by src_ip, uri_path, severity
```

### DDoS Detection
```spl
index=webserver sourcetype=access_combined OR sourcetype=csv_access_logs
| bucket _time span=1m
| stats count by _time, src_ip
| where count > 100
| eval threat_level="HIGH"
```

## 5. FORENSIC ANALYSIS SEARCHES

### Attack Timeline Analysis
```spl
index=webserver sourcetype=access_combined OR sourcetype=csv_access_logs src_ip="SUSPICIOUS_IP"
| eval attack_type=case(
    match(uri_path, "(?i)(union|select)"), "SQL Injection",
    match(uri_path, "\.\./"), "Directory Traversal",
    match(uri_path, "(?i)admin"), "Admin Access",
    status IN ("401","403"), "Authentication Failure",
    1=1, "Normal"
)
| sort _time
| table _time, src_ip, http_method, uri_path, status, attack_type, http_user_agent
```

### Payload Analysis
```spl
index=webserver sourcetype=access_combined OR sourcetype=csv_access_logs
| where len(uri_path) > 100
| eval suspicious_chars=if(match(uri_path, "[<>\"'%;()&+]"), "YES", "NO")
| eval url_decoded=urldecode(uri_path)
| table _time, src_ip, uri_path, url_decoded, suspicious_chars, status
| sort -len(uri_path)
```

### Session Reconstruction
```spl
index=webserver sourcetype=access_combined OR sourcetype=csv_access_logs src_ip="ATTACKER_IP"
| sort _time
| streamstats count as session_request_number by src_ip
| eval time_diff=_time-lag(_time)
| eval new_session=if(time_diff>1800,1,0)
| accum new_session as session_id
| stats values(uri_path) as paths, values(status) as statuses, 
        min(_time) as session_start, max(_time) as session_end, 
        count as total_requests by src_ip, session_id
| eval session_duration=session_end-session_start
```

## 6. PERFORMANCE AND MONITORING

### Top Attack Sources
```spl
index=webserver sourcetype=access_combined OR sourcetype=csv_access_logs
| where status>=400 OR match(uri_path, "(?i)(admin|login|sql|script)")
| stats count by src_ip
| lookup geoip_lookup client_ip as src_ip OUTPUT country
| sort -count
| head 20
```

### Attack Trends Over Time
```spl
index=webserver sourcetype=access_combined OR sourcetype=csv_access_logs
| eval attack_indicator=if(
    match(uri_path, "(?i)(union|select|admin|login|\.\./|script)") OR status IN ("401","403","404"),
    "Attack", "Normal"
)
| bucket _time span=1h
| stats count by _time, attack_indicator
| xyseries _time attack_indicator count
| fillnull value=0
```

### Security Metrics Dashboard
```spl
index=webserver sourcetype=access_combined OR sourcetype=csv_access_logs
| stats count as total_requests,
        sum(eval(if(status>=400,1,0))) as error_requests,
        dc(src_ip) as unique_ips,
        sum(eval(if(match(uri_path, "(?i)(admin|login)"),1,0))) as auth_attempts,
        sum(eval(if(match(uri_path, "(?i)(union|select)"),1,0))) as sql_injection_attempts
| eval error_rate=round(error_requests/total_requests*100,2)
| eval attack_rate=round((auth_attempts+sql_injection_attempts)/total_requests*100,4)
```
