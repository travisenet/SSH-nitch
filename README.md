# SSH-nitch

**Because sometimes you need to tell on the bad IPs!**

SSH-nitch is an automated SSH abuse reporting tool that detects brute force attempts and reports them to the appropriate abuse contacts. It leverages AI to intelligently process WHOIS data and generate professional abuse reports.

![SSH-nitch Logo](https://via.placeholder.com/400x150?text=SSH-nitch)

## 🚨 What It Does

SSH-nitch monitors your Fail2Ban SSH jail and automatically:

1. Retrieves banned IP addresses that attempted to brute force your SSH
2. Performs WHOIS lookups on these IPs
3. Uses AI to extract the correct abuse contact email from WHOIS data
4. Generates a professional, contextually appropriate abuse report
5. Sends the report via email to the responsible abuse team
6. Tracks all reports to prevent duplicates and respect frequency limits

## 🛠️ Current Features

- **Fail2Ban Integration**: Pulls banned IPs directly from your Fail2Ban installation
- **AI-Powered WHOIS Parsing**: Uses Claude 3 to intelligently extract abuse contact information
- **Smart Report Generation**: Leverages Claude 3 to create contextually appropriate abuse reports
- **Email Automation**: Sends reports via Mailgun with proper headers and formatting
- **Intelligent Deduplication**: Prevents sending duplicate reports within configurable timeframes
- **IP Filtering**: Automatically excludes private/reserved IP addresses and custom exclusions
- **Configurable Limits**: Set daily report quotas and frequency restrictions
- **Comprehensive Logging**: Detailed logging of all operations
- **Error Resilience**: Fallback mechanisms when services are unavailable

## 🔮 Planned Features

- **Repeat Offender Tracking**: Enhanced monitoring of IPs/networks that repeatedly cause issues
- **Escalation System**: Automatically escalate reports for persistent offenders
- **Metrics Collection & Analysis**: Gather data on attack patterns, response times, and resolution rates
- **Response Tracking**: Monitor and analyze responses from abuse teams
- **Effectiveness Scoring**: Rate abuse contacts based on their responsiveness and effectiveness
- **Web Dashboard**: Visualize attack patterns and abuse report metrics
- **Multi-Service Integration**: Expand beyond SSH to monitor additional services
- **Geographic Analysis**: Map attacks and identify hotspots
- **Automated Follow-ups**: Send reminders to unresponsive abuse contacts
- **Network Range Correlation**: Identify attacks from related network blocks
- **ISP Reporting Cards**: Generate effectiveness ratings for different providers
- **Threat Intelligence Integration**: Cross-reference with known malicious IPs

## 📋 Requirements

- Python 3.8+
- Fail2Ban
- Anthropic API key (for Claude 3)
- Mailgun account
- WHOIS command-line utility

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/ssh-nitch.git
cd ssh-nitch

# Install required packages
pip install -r requirements.txt

# Copy and edit the configuration file
cp config.example.json config.json
nano config.json  # Add your API keys and settings
```

## ⚙️ Configuration

Edit the `config.json` file with your settings:

```json
{
  "fail2ban_jail": "sshd",
  "anthropic_api_key": "YOUR_ANTHROPIC_API_KEY",
  "anthropic_model": "claude-3-haiku-20240307",
  "mailgun_api_key": "YOUR_MAILGUN_API_KEY",
  "mailgun_domain": "yourdomain.com",
  "mailgun_from_email": "security@yourdomain.com",
  "mailgun_reply_to": "security-noreply@yourdomain.com",
  "report_frequency_hours": 24,
  "max_reports_per_day": 50,
  "whois_timeout": 10,
  "report_template": "...",
  "exclude_ips": [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
  ],
  "log_level": "INFO",
  "database_file": "reported_ips.json",
  "use_env_for_keys": true
}
```

## 🏃‍♂️ Usage

Run manually:

```bash
python log_squealer.py config.json
```

For automated execution, add to crontab:

```
0 */6 * * * /path/to/python /path/to/log_squealer.py /path/to/config.json
```

## 📊 Database

SSH-nitch maintains a database of reported IPs in the specified `database_file`. This JSON file tracks:

- When each IP was last reported
- How many times each IP has been reported
- Response information from abuse contacts
- Associated WHOIS data

This database will be enhanced in future releases to support the planned metrics and repeat offender tracking functionality.

## 🔒 Security Considerations

- API keys are stored in the configuration file. Use `use_env_for_keys: true` and environment variables for better security.
- The tool does not store full logs of SSH attacks, only the IP addresses that were reported.
- All email communication is via Mailgun's API over HTTPS.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.
