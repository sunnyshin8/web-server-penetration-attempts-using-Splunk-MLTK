# Web Server Penetration Detection - Installation Guide

## Prerequisites

### System Requirements
- **Splunk Enterprise** 8.0+ or **Splunk Cloud**
- **Machine Learning Toolkit (MLTK)** 5.0+
- **Python 3.7+** (for data preprocessing)
- **Minimum 8GB RAM** (16GB recommended for large datasets)
- **50GB free disk space** (for index storage)

### Required Splunk Apps
1. **Splunk Machine Learning Toolkit**
   ```bash
   # Install from Splunkbase or command line
   $SPLUNK_HOME/bin/splunk install app $MLTK_PACKAGE.tgz
   ```

2. **Common Information Model (CIM)**
   ```bash
   $SPLUNK_HOME/bin/splunk install app $CIM_PACKAGE.tgz
   ```

3. **Python for Scientific Computing**
   ```bash
   $SPLUNK_HOME/bin/splunk install app $PYTHON_SCIENTIFIC_PACKAGE.tgz
   ```

## Installation Steps

### 1. Data Preparation

#### Parse Apache Logs
```bash
cd "web server penetration attempts using Splunk MLTK"
python parse_apache_log.py
```

#### Verify Parsed Data
```bash
# Check the first few lines of parsed data
head -20 access_parsed.csv
```

### 2. Splunk Configuration

#### Configure Index
```bash
# Create dedicated index for web server logs
$SPLUNK_HOME/bin/splunk add index webserver -homePath $SPLUNK_DB/webserver/db -coldPath $SPLUNK_DB/webserver/colddb -thawedPath $SPLUNK_DB/webserver/thaweddb
```

#### Deploy Configuration Files
```bash
# Copy configuration files to Splunk
cp splunk_configs/props.conf $SPLUNK_HOME/etc/system/local/
cp splunk_configs/transforms.conf $SPLUNK_HOME/etc/system/local/
cp splunk_configs/inputs.conf $SPLUNK_HOME/etc/system/local/

# Restart Splunk to apply changes
$SPLUNK_HOME/bin/splunk restart
```

### 3. Data Ingestion

#### Upload CSV Data
1. Navigate to **Settings > Add Data**
2. Select **Upload** option
3. Upload `access_parsed.csv`
4. Set sourcetype to `csv_access_logs`
5. Set index to `webserver`

#### Configure Real-time Ingestion (Optional)
```bash
# For real-time log monitoring
[monitor:///var/log/apache2/access.log]
disabled = false
sourcetype = access_combined
index = webserver
```

### 4. Machine Learning Models Setup

#### Install Python Dependencies
```bash
# Install required Python packages
pip install pandas numpy scikit-learn matplotlib seaborn

# Or using requirements file
pip install -r requirements.txt
```

#### Train Initial Models
```bash
cd ml_models
python security_ml_models.py
```

### 5. Dashboard Installation

#### Import Dashboard Configurations
1. Navigate to **Settings > User Interface > Views**
2. Click **New View**
3. Copy content from `dashboards/security_dashboards.json`
4. Save as XML dashboard file

#### Alternative: Manual Dashboard Creation
1. Go to **Search & Reporting**
2. Create new dashboard
3. Add panels using search queries from `splunk_configs/search_queries.md`

### 6. Alert Configuration

#### Import Alert Rules
```bash
# Copy alert configurations
cp alerts/security_alerts.conf $SPLUNK_HOME/etc/system/local/savedsearches.conf

# Reload configuration
$SPLUNK_HOME/bin/splunk reload
```

#### Configure Email Settings
1. Navigate to **Settings > Server Settings > Email Settings**
2. Configure SMTP server details
3. Test email connectivity

### 7. Verification and Testing

#### Test Data Ingestion
```spl
index=webserver earliest=-1h
| stats count by sourcetype
```

#### Verify Field Extraction
```spl
index=webserver earliest=-1h
| table _time, src_ip, http_method, uri_path, status, http_user_agent
| head 10
```

#### Test Attack Detection
```spl
index=webserver earliest=-1h
| regex uri_path="(?i)(union|select|admin)"
| stats count by src_ip, uri_path
```

## Configuration Tuning

### Performance Optimization

#### Accelerate Data Models
```spl
| datamodel Web_Intelligence search
| acceleration.max_time = 1d
| acceleration.earliest_time = -30d@d
```

#### Optimize Search Performance
```bash
# Add to limits.conf
[search]
max_searches_per_cpu = 8
base_max_searches = 6
max_rt_search_multiplier = 10
```

### Detection Tuning

#### Adjust Anomaly Thresholds
```python
# In security_ml_models.py
isolation_forest = IsolationForest(
    contamination=0.05,  # Adjust based on environment
    n_estimators=200,    # Increase for better accuracy
    random_state=42
)
```

#### Customize Attack Patterns
```conf
# In transforms.conf - Add organization-specific patterns
[custom_attack_regex]
REGEX = (?i)(your_custom_pattern|specific_vulnerability)
```

### Alert Fine-tuning

#### Reduce False Positives
```spl
# Exclude known good IPs
index=webserver NOT (src_ip IN ("192.168.1.100", "10.0.0.50"))
| your_search_logic_here
```

#### Whitelist Legitimate Bots
```spl
# Exclude legitimate crawlers
index=webserver NOT (http_user_agent="Googlebot*" OR http_user_agent="Bingbot*")
| your_bot_detection_logic
```

## Troubleshooting

### Common Issues

#### 1. Data Not Appearing in Index
```bash
# Check data input status
$SPLUNK_HOME/bin/splunk list inputstatus

# Verify index exists
$SPLUNK_HOME/bin/splunk list index
```

#### 2. Field Extraction Not Working
```spl
# Test regex patterns
| rex field=_raw "your_regex_pattern"
| table extracted_field
```

#### 3. ML Models Not Training
```bash
# Check Python environment
$SPLUNK_HOME/bin/splunk cmd python3 -c "import pandas, sklearn"

# Verify MLTK installation
$SPLUNK_HOME/bin/splunk list apps | grep -i mltk
```

#### 4. Alerts Not Firing
```spl
# Test alert search manually
your_alert_search_here
| head 10
```

### Log Analysis

#### Monitor Splunk Internal Logs
```spl
index=_internal source=*splunkd.log* component=AggregatorMiningProcessor
| stats count by component
```

#### Check Search Performance
```spl
index=_audit action=search
| eval search_time=total_run_time
| stats avg(search_time) by user
```

## Security Considerations

### Access Control
```bash
# Create security role
$SPLUNK_HOME/bin/splunk add role security_analyst -capability search
$SPLUNK_HOME/bin/splunk edit role security_analyst -addcapability alert_create
```

### Data Retention
```conf
# In indexes.conf
[webserver]
maxDataSize = 500000
maxHotBuckets = 10
maxWarmDBCount = 300
```

### Audit Trail
```spl
# Monitor configuration changes
index=_audit object_category=conf_*
| stats count by object, action, user
```

## Maintenance

### Regular Tasks

#### Weekly Model Retraining
```bash
#!/bin/bash
# Add to crontab: 0 2 * * 0
cd /path/to/ml_models
python security_ml_models.py --retrain
```

#### Monthly Performance Review
```spl
# Alert effectiveness analysis
index=_audit action=alert_fired
| stats count by alert_name, result_count
| eval effectiveness=if(result_count>0, "effective", "needs_tuning")
```

#### Quarterly Threat Intelligence Update
```bash
# Update threat intelligence feeds
curl -o threat_intel.csv "https://your-threat-intel-feed.com/latest"
$SPLUNK_HOME/bin/splunk reload
```

## Support and Documentation

### Resources
- **Splunk Documentation**: https://docs.splunk.com/
- **MLTK Documentation**: https://docs.splunk.com/Documentation/MLApp/
- **CIM Documentation**: https://docs.splunk.com/Documentation/CIM/

### Community Support
- **Splunk Community**: https://community.splunk.com/
- **GitHub Issues**: Create issues for project-specific problems
- **Security Forums**: Share detection techniques and improvements

### Professional Services
- **Splunk Professional Services**: For enterprise implementations
- **Security Consulting**: For advanced threat detection requirements
- **Training Programs**: Splunk certification and specialized security training
