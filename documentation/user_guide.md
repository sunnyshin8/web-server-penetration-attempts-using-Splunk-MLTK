# Web Server Penetration Detection - User Guide

## Overview

This user guide provides comprehensive instructions for using the Web Server Penetration Detection system built on Splunk MLTK. The system analyzes web server access logs to identify and alert on potential security threats, penetration attempts, and anomalous behavior.

## Getting Started

### Accessing the System

1. **Log into Splunk Web Interface**
   - URL: `https://your-splunk-server:8000`
   - Use your assigned credentials
   - Navigate to the **Security App** or **Search & Reporting**

2. **Verify Data Availability**
   ```spl
   index=webserver
   | stats count by sourcetype
   | sort -count
   ```

### Understanding the Data Model

#### Key Fields
- **src_ip**: Source IP address of the request
- **http_method**: HTTP method (GET, POST, PUT, DELETE, etc.)
- **uri_path**: Requested URL path
- **status**: HTTP response status code
- **http_user_agent**: Client user agent string
- **bytes_in/bytes_out**: Request and response sizes
- **_time**: Timestamp of the request

#### Derived Security Fields
- **is_error**: Boolean flag for HTTP errors (4xx/5xx)
- **has_sql_injection**: Indicates potential SQL injection patterns
- **has_directory_traversal**: Flags directory traversal attempts
- **has_admin_access**: Identifies admin panel access attempts
- **is_bot**: Flags automated bot traffic

## Using the Dashboards

### 1. Security Overview Dashboard

#### Purpose
Provides high-level security metrics and trends for executive reporting and daily monitoring.

#### Key Panels
- **Attack Volume Trends**: Timeline showing attack attempts over time
- **Top Threat Sources**: Countries and IPs generating the most threats
- **Attack Type Distribution**: Breakdown of different attack categories
- **Response Code Analysis**: HTTP status code patterns

#### How to Use
1. Navigate to **Dashboards > Security Overview**
2. Adjust time range using the time picker (default: last 24 hours)
3. Click on visualizations to drill down into specific data
4. Use filters to focus on specific attack types or IP ranges

#### Example Queries Behind the Panels
```spl
# Attack volume over time
index=webserver
| eval attack_indicator=if(
    match(uri_path, "(?i)(union|select|admin|login|script)") OR status>=400,
    "attack", "normal"
)
| timechart span=1h count by attack_indicator
```

### 2. Threat Analysis Dashboard

#### Purpose
Deep-dive analysis of specific threats and attack patterns for security analysts.

#### Key Panels
- **SQL Injection Analysis**: Detailed view of injection attempts
- **Brute Force Timeline**: Authentication attack patterns
- **Suspicious User Agents**: Bot and scanner identification
- **Path Analysis**: Analysis of requested URLs and payloads

#### Advanced Features
- **Real-time Updates**: Auto-refresh every 30 seconds
- **Drill-down Capability**: Click any data point for detailed investigation
- **Correlation Views**: See related attacks from same sources

### 3. Real-time Monitoring Dashboard

#### Purpose
Live monitoring for immediate threat response and situational awareness.

#### Key Features
- **Threat Level Indicator**: Current overall threat status
- **Active Attack Counter**: Number of ongoing attacks
- **Live Attack Feed**: Real-time stream of security events
- **Critical Alerts**: Immediate notifications for severe threats

#### Response Actions
- **Block IP**: Direct integration with firewall systems
- **Escalate Alert**: Send to security team lead
- **Create Incident**: Automatically generate incident tickets

## Search Techniques

### Basic Threat Hunting

#### 1. Finding SQL Injection Attempts
```spl
index=webserver
| regex uri_path="(?i)(union|select|insert|update|delete|drop)"
| eval decoded_path=urldecode(uri_path)
| table _time, src_ip, decoded_path, status, http_user_agent
| sort -_time
```

#### 2. Identifying Brute Force Attacks
```spl
index=webserver
| where status IN ("401", "403") OR match(uri_path, "(?i)(login|auth)")
| bucket _time span=5m
| stats count as attempts by _time, src_ip
| where attempts > 10
| sort -attempts
```

#### 3. Detecting Directory Traversal
```spl
index=webserver
| regex uri_path="(\.\./|\.\.%2f|\.\.%5c)"
| eval attack_payload=urldecode(uri_path)
| stats count, values(attack_payload) as payloads by src_ip
| sort -count
```

#### 4. Analyzing Suspicious File Access
```spl
index=webserver
| regex uri_path="(?i)\.(php|asp|jsp|cgi|sh|exe|bat)(\?.*)?$"
| where NOT match(uri_path, "(?i)(index|default|main)")
| stats count, dc(uri_path) as unique_files by src_ip
| where count > 5
| sort -count
```

### Advanced Analytics

#### 1. Anomaly Detection with MLTK
```spl
index=webserver
| bucket _time span=1h
| stats count as requests, dc(uri_path) as unique_paths, 
        sum(eval(if(status>=400,1,0))) as errors by _time, src_ip
| eval error_rate=errors/requests
| fit IsolationForest requests unique_paths error_rate
| where outlier="True"
| sort -requests
```

#### 2. Clustering Analysis for Attack Patterns
```spl
index=webserver
| where status>=400
| eval path_length=len(uri_path)
| eval special_chars=if(match(uri_path, "[<>\"';()&+%]"), 1, 0)
| eval numeric_status=tonumber(status)
| fit DBSCAN path_length special_chars numeric_status eps=0.5 minpts=10
| where cluster!=-1
| stats count by cluster, status
| sort cluster, -count
```

#### 3. User Agent Analysis
```spl
index=webserver
| where len(http_user_agent) < 20 OR len(http_user_agent) > 500
| stats count, dc(src_ip) as unique_ips, dc(uri_path) as unique_paths 
        by http_user_agent
| where count > 10
| eval suspicion_score=(count*0.4 + unique_ips*0.3 + unique_paths*0.3)
| sort -suspicion_score
```

### Geographic Analysis

#### IP Geolocation Analysis
```spl
index=webserver
| where status>=400
| iplocation src_ip
| stats count as attacks by Country, Region, City
| geostats latfield=lat longfield=lon count
```

#### Country-based Threat Assessment
```spl
index=webserver
| iplocation src_ip
| eval attack_type=case(
    match(uri_path, "(?i)(union|select)"), "SQL Injection",
    match(uri_path, "\.\./"), "Directory Traversal",
    match(uri_path, "(?i)admin"), "Admin Access",
    status IN ("401","403"), "Auth Failure",
    1=1, "Other"
)
| where attack_type != "Other"
| stats count by Country, attack_type
| sort Country, -count
```

## Alert Management

### Understanding Alert Severity

#### Critical (Level 3)
- SQL Injection attempts
- Directory Traversal attacks
- Command Injection attempts
- XSS attacks
- Immediate response required

#### High (Level 2)
- Brute Force attacks
- Admin panel access attempts
- High error rates
- Response within 30 minutes

#### Medium (Level 1)
- Suspicious bot activity
- Unusual traffic patterns
- Monitor and investigate

### Alert Response Procedures

#### 1. Critical Alert Response
```
IMMEDIATE ACTIONS (0-5 minutes):
1. Acknowledge alert in Splunk
2. Block source IP at perimeter firewall
3. Notify security team lead via phone/Slack
4. Document initial findings in incident system

INVESTIGATION (5-30 minutes):
1. Analyze full attack session from source IP
2. Check for data exfiltration indicators
3. Review application logs for successful exploitation
4. Identify vulnerable components

CONTAINMENT (30-60 minutes):
1. Apply emergency patches if available
2. Implement WAF rules to block attack pattern
3. Monitor for lateral movement
4. Prepare detailed incident report
```

#### 2. High Alert Response
```
INITIAL RESPONSE (0-15 minutes):
1. Acknowledge alert
2. Rate limit source IP
3. Notify security analyst on duty

ANALYSIS (15-45 minutes):
1. Determine if attack was successful
2. Check for compromised accounts
3. Review related log entries

MITIGATION (45-90 minutes):
1. Implement additional security controls
2. Update detection rules if needed
3. Schedule follow-up monitoring
```

### Custom Alert Creation

#### Creating a New Alert
1. **Navigate to Settings > Searches, Reports, and Alerts**
2. **Click "New Alert"**
3. **Configure Alert Parameters:**
   ```
   Title: Custom Security Alert
   Search: your_search_query_here
   Schedule: */10 * * * * (every 10 minutes)
   Trigger Conditions: Number of results > 0
   ```
4. **Set Alert Actions:**
   - Email notification
   - Webhook to Slack/Teams
   - Script execution for automated response

#### Example Custom Alert Search
```spl
index=webserver
| where match(uri_path, "your_custom_pattern")
| stats count by src_ip
| where count > threshold_value
```

## Machine Learning Features

### Pre-built Models

#### 1. Request Volume Anomaly Detection
- **Purpose**: Identifies unusual spikes in traffic that may indicate DDoS or scanning
- **Model Type**: Isolation Forest
- **Update Frequency**: Daily
- **Usage**: Automatic scoring of hourly traffic patterns

#### 2. Path Length Analysis
- **Purpose**: Detects unusually long URLs that often contain attack payloads
- **Model Type**: DBSCAN Clustering
- **Features**: URL length, special character count, parameter count
- **Usage**: Real-time scoring of incoming requests

#### 3. User Agent Clustering
- **Purpose**: Groups similar user agents to identify bot families and attack tools
- **Model Type**: DBSCAN Clustering
- **Features**: User agent length, browser patterns, version information
- **Usage**: Classification of automated vs. human traffic

### Model Retraining

#### When to Retrain
- Weekly for high-traffic environments
- Monthly for normal environments
- After major application changes
- When false positive rates increase

#### Retraining Process
```spl
# Step 1: Collect training data (last 30 days of clean traffic)
index=webserver earliest=-30d@d latest=-1d@d
| where NOT (status>=400 OR match(uri_path, "(?i)(admin|login|sql)"))
| fit IsolationForest ... into updated_model

# Step 2: Test new model on validation set
| apply updated_model
| where outlier="True"
| eval false_positive=if(known_good_traffic=1, 1, 0)
| stats sum(false_positive) as fp_count, count as total_outliers
| eval fp_rate=fp_count/total_outliers

# Step 3: Deploy if performance acceptable (FP rate < 5%)
```

### Custom Model Development

#### Creating Domain-specific Models
```python
# Example: E-commerce specific attack detection
features = [
    'cart_value',           # Shopping cart manipulation
    'checkout_speed',       # Automated purchasing
    'product_enum_rate',    # Product enumeration
    'payment_failures'      # Card testing attempts
]

model = IsolationForest(contamination=0.02)
model.fit(ecommerce_features)
```

## Integration and APIs

### SIEM Integration

#### Forwarding Alerts to External SIEM
```xml
<!-- ArcSight CEF Format -->
<format>CEF:0|Splunk|WebSecurity|1.0|{alert_type}|{alert_name}|{severity}|src={src_ip} dst={server_ip} request={uri_path} cs1={user_agent}</format>
```

#### QRadar Integration
```json
{
  "event_type": "web_attack",
  "source_ip": "$result.src_ip$",
  "severity": "$alert.severity$",
  "attack_type": "$result.attack_type$",
  "timestamp": "$result._time$",
  "raw_event": "$result._raw$"
}
```

### API Access

#### REST API for External Tools
```bash
# Get recent alerts
curl -k -u admin:password "https://splunk:8089/services/search/jobs/export" \
  -d search="search index=webserver | head 100" \
  -d output_mode=json

# Create incident via API
curl -X POST "https://incident-api.company.com/incidents" \
  -H "Content-Type: application/json" \
  -d '{"source":"splunk","severity":"high","description":"Security alert"}'
```

### Webhook Configuration

#### Slack Integration
```json
{
  "webhook_url": "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK",
  "payload": {
    "channel": "#security-alerts",
    "username": "Splunk Security",
    "text": "🚨 *Security Alert*: {alert_type} detected",
    "attachments": [
      {
        "color": "danger",
        "fields": [
          {"title": "Source IP", "value": "{src_ip}", "short": true},
          {"title": "Attack Type", "value": "{attack_type}", "short": true},
          {"title": "Target", "value": "{uri_path}", "short": false}
        ]
      }
    ]
  }
}
```

## Best Practices

### Search Optimization

#### 1. Time Range Selection
- Use specific time ranges instead of "All time"
- Default to last 24 hours for routine investigations
- Use summary indexes for historical analysis

#### 2. Efficient Search Patterns
```spl
# Good: Filter early in the search
index=webserver status>=400
| regex uri_path="pattern"
| stats count by src_ip

# Avoid: Filtering after expensive operations
index=webserver
| stats count by src_ip, uri_path, status
| where status>=400
```

#### 3. Data Model Usage
```spl
# Use data models for consistent field naming
| datamodel Web_Intelligence Web search
| search status>=400
```

### Alert Tuning

#### Reducing False Positives
1. **Whitelist Known Good IPs**
   ```spl
   | where NOT src_ip IN ("192.168.1.100", "10.0.0.50")
   ```

2. **Time-based Filtering**
   ```spl
   | where date_hour>=9 AND date_hour<=17  # Business hours only
   ```

3. **Volume Thresholds**
   ```spl
   | where count > 10  # Require minimum threshold
   ```

### Performance Monitoring

#### Dashboard Performance
- Limit search time ranges
- Use summary indexes for historical data
- Implement search acceleration where appropriate

#### Alert Performance
- Monitor alert execution times
- Review search.log for slow searches
- Optimize search queries regularly

### Security Considerations

#### Data Privacy
- Mask sensitive data in URI parameters
- Implement role-based access controls
- Regular audit of user permissions

#### System Security
- Regular Splunk security updates
- Network segmentation for Splunk infrastructure
- Encrypted data transmission

## Troubleshooting

### Common Issues

#### 1. No Data in Dashboards
**Symptoms**: Empty panels, "No results found"
**Solutions**:
- Verify index permissions: `| rest /services/authorization/roles | search title=your_role`
- Check time range settings
- Verify data ingestion: `index=webserver | stats count by sourcetype`

#### 2. Alerts Not Firing
**Symptoms**: Expected alerts not received
**Solutions**:
- Test alert search manually
- Check alert scheduling: `| rest /services/saved/searches | search is_scheduled=1`
- Verify email configuration
- Review alert suppression settings

#### 3. Poor Search Performance
**Symptoms**: Slow loading dashboards, timeouts
**Solutions**:
- Optimize search queries with early filtering
- Use summary indexes for frequently accessed data
- Review search concurrency limits
- Consider data model acceleration

#### 4. High False Positive Rate
**Symptoms**: Too many irrelevant alerts
**Solutions**:
- Analyze alert patterns: `index=_audit action=alert_fired | stats count by savedsearch_name`
- Implement whitelisting for known good sources
- Adjust detection thresholds
- Retrain machine learning models

### Getting Help

#### Internal Resources
- **Documentation**: Check project documentation folder
- **Search Examples**: Review saved searches and reports
- **Team Knowledge Base**: Internal wiki or confluence

#### External Resources
- **Splunk Community**: https://community.splunk.com/
- **Splunk Documentation**: https://docs.splunk.com/
- **Security Blogs**: Stay updated with latest threat intelligence

#### Support Contacts
- **Security Team Lead**: For critical issues
- **Splunk Administrator**: For system/configuration issues
- **Application Team**: For false positive analysis

## Appendix

### Useful Regular Expressions

#### SQL Injection Patterns
```regex
(?i)(union(\s+(all|distinct))?(\s+select)|select.+(from|limit)|insert(\s+into)?|update(\s+\w+)?(\s+set)|delete(\s+from)?|drop(\s+(table|database))|create(\s+(table|database)))
```

#### XSS Patterns
```regex
(?i)(<script|javascript:|on\w+\s*=|<iframe|<object|<embed|alert\(|confirm\(|prompt\()
```

#### Directory Traversal Patterns
```regex
(\.\./|\.\.%2f|\.\.%5c|%2e%2e%2f|%2e%2e%5c)
```

### HTTP Status Code Reference

| Code Range | Category | Security Relevance |
|------------|----------|-------------------|
| 200-299 | Success | Normal operations |
| 300-399 | Redirection | Potential redirect attacks |
| 400-499 | Client Error | Failed attack attempts |
| 500-599 | Server Error | Successful attacks or DoS |

### Common Attack Vectors

| Attack Type | Indicators | Mitigation |
|-------------|------------|------------|
| SQL Injection | SQL keywords in URL | Input validation, parameterized queries |
| XSS | Script tags, JavaScript | Output encoding, CSP headers |
| CSRF | Unexpected POST requests | CSRF tokens, SameSite cookies |
| Directory Traversal | ../ patterns | Path validation, chroot |
| Brute Force | Multiple auth failures | Rate limiting, account lockout |
