#!/usr/bin/env python3
"""
SSH Abuse Reporter

This script automatically detects SSH brute force attempts and reports them to the 
appropriate abuse contacts. It leverages Fail2Ban for IP detection, Claude 3 API for 
intelligent WHOIS parsing and report generation, and Mailgun for email delivery.

Author: Senior Cybersecurity Python Developer
Date: March 28, 2025
"""

import os
import sys
import json
import time
import logging
import ipaddress
import subprocess
import requests
import smtplib
import email.utils
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from typing import Dict, List, Set, Tuple, Optional, Any, Union
from dataclasses import dataclass
import anthropic
import re
import socket

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("ssh_abuse_reporter.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("ssh_abuse_reporter")

@dataclass
class Config:
    """Configuration class to store all settings."""
    fail2ban_jail: str
    anthropic_api_key: str
    anthropic_model: str
    mailgun_api_key: str
    mailgun_domain: str
    mailgun_from_email: str
    mailgun_reply_to: str
    report_frequency_hours: int
    max_reports_per_day: int
    whois_timeout: int
    report_template: str
    exclude_ips: List[str]
    log_level: str
    database_file: str
    use_env_for_keys: bool = False
    history_days: int = 7  # Default to 7 days of history


class IPDatabase:
    """Manages reported IPs to prevent duplicate reports."""
    
    def __init__(self, db_file: str):
        self.db_file = db_file
        self.reported_ips = self._load_database()
        
    def _load_database(self) -> Dict[str, Dict[str, Any]]:
        """Load the database from file or create if it doesn't exist."""
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                logger.error(f"Error decoding database file {self.db_file}. Creating new database.")
                return {}
        else:
            return {}
    
    def _save_database(self) -> None:
        """Save the database to file."""
        with open(self.db_file, 'w') as f:
            json.dump(self.reported_ips, f, indent=2)
    
    def can_report_ip(self, ip: str, frequency_hours: int) -> bool:
        """Check if an IP can be reported based on the last report time."""
        now = datetime.now()
        if ip in self.reported_ips:
            last_report_time = datetime.fromisoformat(self.reported_ips[ip]["last_reported"])
            if (now - last_report_time) < timedelta(hours=frequency_hours):
                return False
        return True
    
    def add_reported_ip(self, ip: str, report_info: Dict[str, Any]) -> None:
        """Add or update a reported IP in the database."""
        if ip in self.reported_ips:
            self.reported_ips[ip]["report_count"] += 1
        else:
            self.reported_ips[ip] = {"report_count": 1}
        
        self.reported_ips[ip]["last_reported"] = datetime.now().isoformat()
        self.reported_ips[ip]["last_report_info"] = report_info
        self._save_database()
    
    def get_report_count_today(self) -> int:
        """Get the count of reports sent today."""
        today = datetime.now().date()
        count = 0
        
        for ip, data in self.reported_ips.items():
            last_report_date = datetime.fromisoformat(data["last_reported"]).date()
            if last_report_date == today:
                count += 1
        
        return count


class Fail2BanHandler:
    """Handles interaction with Fail2Ban to retrieve banned IPs."""
    
    def __init__(self, jail: str):
        self.jail = jail
        # Path to Fail2Ban logs - may need adjustment based on your system
        self.log_path = "/var/log/fail2ban.log"
    
    def get_banned_ips(self) -> List[str]:
        """Get a list of IPs currently banned by Fail2Ban."""
        try:
            # Try to run with sudo if not running as root
            if os.geteuid() != 0:
                cmd = ["sudo", "fail2ban-client", "status", self.jail]
            else:
                cmd = ["fail2ban-client", "status", self.jail]
                
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                check=True
            )
            
            # Parse the output to extract IPs
            match = re.search(r"Banned IP list:\s*(.*)", result.stdout)
            if match and match.group(1):
                return match.group(1).strip().split()
            
            logger.warning(f"No banned IPs found in jail {self.jail}")
            return []
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Error executing fail2ban-client: {str(e)}")
            logger.debug(f"Command output: {e.stderr}")
            return []
    
    def get_historical_banned_ips(self, days_back: int = 7) -> Dict[str, List[datetime]]:
        """Get historical banned IPs from Fail2Ban database."""
        banned_ips = {}
        # Add at the beginning of get_historical_banned_ips()

        try:
            # Calculate the date from which to start searching
            start_time = int((datetime.now() - timedelta(days=days_back)).timestamp())
            logger.debug(f"Searching for banned IPs in jail {self.jail} since {start_time}")
            logger.debug(f"Using log path: {self.log_path}")       
            # Command to query the Fail2Ban database
            if os.geteuid() != 0:
                cmd = ["sudo", "fail2ban-client", "get", self.jail, "banned"]
            else:
                cmd = ["fail2ban-client", "get", self.jail, "banned"]
                
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                logger.error(f"Error querying Fail2Ban database: {result.stderr}")
                return banned_ips
            
            # Process the output (format varies by Fail2Ban version)
            ip_list = []
            for line in result.stdout.strip().split('\n'):
                if line and not line.startswith('-') and not line.lower() == 'none':
                    ip_list.extend(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line))
            
            # For each IP, get its ban history
            for ip in ip_list:
                banned_ips[ip] = [datetime.now()]  # Default to current time
                
            logger.info(f"Found {len(banned_ips)} historical banned IPs from Fail2Ban database")
            return banned_ips
        
        except Exception as e:
            logger.error(f"Error retrieving historical banned IPs from database: {str(e)}")
            return banned_ips

class WHOISParser:
    """Handles WHOIS lookups and parses results to find abuse contacts."""
    
    def __init__(self, anthropic_client, model: str, timeout: int):
        self.anthropic_client = anthropic_client
        self.model = model
        self.timeout = timeout
        
    def get_whois_data(self, ip: str) -> str:
        """Get WHOIS data for an IP address."""
        try:
            result = subprocess.run(
                ["whois", ip], 
                capture_output=True, 
                text=True, 
                timeout=self.timeout
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            logger.warning(f"WHOIS lookup timed out for IP {ip}")
            return ""
        except Exception as e:
            logger.error(f"Error during WHOIS lookup for IP {ip}: {str(e)}")
            return ""
    
    def extract_abuse_contact(self, whois_data: str, ip: str) -> Tuple[Optional[str], Dict[str, Any]]:
        """
        Use Claude 3 to extract abuse contact information from WHOIS data.
        Returns the email address and additional metadata.
        """
        if not whois_data:
            return None, {"error": "Empty WHOIS data"}
        
        try:
            # Prepare the prompt for Claude 3
            prompt = f"""
            You are a cybersecurity expert analyzing WHOIS data to find the best abuse contact email.
            
            Given the following WHOIS data for IP {ip}, extract the most appropriate email address for reporting abuse.
            
            Focus on fields like:
            - abuse-mailbox
            - abuse-c
            - abuse email
            - abuse contact
            - OrgAbuseEmail
            - e-mail
            
            If multiple abuse emails exist, select the most specific one for handling network abuse.
            
            WHOIS DATA:
            {whois_data}
            
            Respond with a JSON object containing:
            1. "abuse_email": The best email for reporting abuse (null if none found)
            2. "organization": The organization name if present (null if none found)
            3. "network_details": CIDR or network range if present (null if none found)
            4. "alternative_contacts": Array of other possible contact emails (empty if none found)
            5. "country": Country code if present (null if none found)
            """
            
            # Call Claude 3 API
            response = self.anthropic_client.messages.create(
                model=self.model,
                max_tokens=1024,
                system="You are a cybersecurity expert that parses WHOIS data to find abuse contacts. Always respond in valid JSON format only.",
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            # Extract and parse the JSON response
            try:
                result = json.loads(response.content[0].text)
                logger.debug(f"Parsed abuse contact for {ip}: {result}")
                return result.get("abuse_email"), result
            except json.JSONDecodeError:
                logger.error(f"Failed to parse JSON response from Claude API for IP {ip}")
                logger.debug(f"Response: {response.content[0].text}")
                return None, {"error": "Invalid JSON response"}
                
        except Exception as e:
            logger.error(f"Error extracting abuse contact for IP {ip}: {str(e)}")
            return None, {"error": str(e)}


class AbuseReportGenerator:
    """Generates abuse reports using Claude 3."""
    
    def __init__(self, anthropic_client, model: str, template: str):
        self.anthropic_client = anthropic_client
        self.model = model
        self.template = template
    
    def generate_report(self, ip: str, whois_info: Dict[str, Any], server_info: Dict[str, Any]) -> str:
        """Generate a professional abuse report using Claude 3."""
        try:
            # Create a prompt for Claude 3
            prompt = f"""
            Generate a professional network abuse report using the following information.
            
            TEMPLATE:
            {self.template}
            
            INFORMATION TO INCLUDE:
            - Offending IP Address: {ip}
            - Organization: {whois_info.get('organization', 'Unknown')}
            - Country: {whois_info.get('country', 'Unknown')}
            - Network Details: {whois_info.get('network_details', 'Unknown')}
            
            SERVER INFORMATION:
            - Server Hostname: {server_info.get('hostname', 'Unknown')}
            - Attack Detected: SSH brute force attempt
            - Time of Detection: {server_info.get('detection_time', datetime.now().isoformat())}
            - Number of Failed Attempts: {server_info.get('attempt_count', 'Multiple')}
            
            REPEAT OFFENDER DATA:
            - First Seen: {server_info.get('first_seen', 'Unknown')}
            - Number of Previous Bans: {server_info.get('ban_count', 0)}
            - Is Repeat Offender: {server_info.get('is_repeat_offender', False)}
            """
            
            # Add additional repeat offender data if available
            if server_info.get('is_repeat_offender', False):
                prompt += f"""
                - Average Hours Between Bans: {server_info.get('avg_hours_between_bans', 'Unknown')}
                - Latest Ban: {server_info.get('latest_ban', 'Unknown')}
                
                Since this is a repeat offender, emphasize the pattern of abuse and request stronger action.
                """
            
            prompt += """
            Write a professional, formal report that:
            1. Clearly states the issue
            2. Provides specific details about the attack
            3. Requests appropriate action
            4. Offers to provide additional information if needed
            5. Thanks the recipient for their attention to this matter
            
            Use a firm but professional tone. Do not be accusatory, but be clear about the severity of the issue.
            """
            
            # Call Claude 3 API
            response = self.anthropic_client.messages.create(
                model=self.model,
                max_tokens=2048,
                system="You are a cybersecurity professional who writes clear, effective abuse reports. Be concise but thorough.",
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            return response.content[0].text.strip()
            
        except Exception as e:
            logger.error(f"Error generating abuse report for IP {ip}: {str(e)}")
            return self._get_fallback_report(ip, whois_info, server_info)
    
    def _get_fallback_report(self, ip: str, whois_info: Dict[str, Any], server_info: Dict[str, Any]) -> str:
        """Generate a fallback report if the API call fails."""
        org = whois_info.get('organization', 'your organization')
        detection_time = server_info.get('detection_time', datetime.now().isoformat())
        hostname = server_info.get('hostname', socket.gethostname())
        is_repeat = server_info.get('is_repeat_offender', False)
        ban_count = server_info.get('ban_count', 0)
        
        subject = f"SSH Brute Force Attack Report from {hostname}"
        
        if is_repeat:
            subject = f"REPEAT OFFENDER: {subject}"
        
        body = f"""
        Subject: {subject}

        Dear Abuse Team at {org},

        We are writing to report malicious SSH brute force attempts originating from IP address {ip} against our server {hostname}. These attempts were detected on {detection_time}.
        """
        
        if is_repeat:
            first_seen = server_info.get('first_seen', 'an earlier date')
            body += f"""
            THIS IS A REPEAT OFFENDER. This IP address has been banned {ban_count} times since {first_seen}. 
            The persistent nature of these attacks suggests a deliberate and ongoing attempt to compromise our systems.
            """
        
        body += """
        Our automated security systems have detected repeated failed SSH login attempts, which is consistent with brute force attack patterns. This activity violates acceptable use policies and potentially computer abuse laws.

        We request that you investigate this issue and take appropriate action to stop this malicious activity.
        """
        
        if is_repeat:
            body += "\nGiven the repeated nature of these attacks, we urge you to take stronger measures to prevent further abuse from this IP address."
        
        body += """
        Please let us know if you require any additional information.

        Regards,
        Security Team
        """
        
        return body


class EmailSender:
    """Handles sending emails via Mailgun."""
    
    def __init__(self, api_key: str, domain: str, from_email: str, reply_to: str):
        self.api_key = api_key
        self.domain = domain
        self.from_email = from_email
        self.reply_to = reply_to
        self.base_url = f"https://api.mailgun.net/v3/{domain}/messages"
    
    def send_report(self, to_email: str, subject: str, body: str, ip: str) -> Tuple[bool, Dict[str, Any]]:
        """Send an abuse report via Mailgun."""
        try:
            data = {
                "from": self.from_email,
                "to": to_email,
                "subject": subject,
                "text": body,
                "h:Reply-To": self.reply_to,
                "h:X-Abuse-Report": "true",
                "h:X-Reported-IP": ip
            }
            
            response = requests.post(
                self.base_url,
                auth=("api", self.api_key),
                data=data
            )
            
            response_data = response.json()
            
            if response.status_code == 200:
                logger.info(f"Successfully sent abuse report for IP {ip} to {to_email}")
                return True, response_data
            else:
                logger.error(f"Failed to send email: {response.status_code} - {response_data}")
                return False, response_data
                
        except Exception as e:
            logger.error(f"Error sending email for IP {ip}: {str(e)}")
            return False, {"error": str(e)}


class SSHAbuseReporter:
    """Main class that orchestrates the SSH abuse reporting workflow."""
    
    def __init__(self, config_file: str):
        self.config = self._load_config(config_file)
        self.setup()
    
    def _load_config(self, config_file: str) -> Config:
        """Load configuration from a JSON file."""
        try:
            with open(config_file, 'r') as f:
                config_data = json.load(f)
            
            # Configure logging level based on config
            logging.getLogger().setLevel(getattr(logging, config_data.get("log_level", "INFO")))
            
            # Load environment variables for sensitive information if specified
            if config_data.get("use_env_for_keys", False):
                config_data["anthropic_api_key"] = os.environ.get("ANTHROPIC_API_KEY", config_data.get("anthropic_api_key", ""))
                config_data["mailgun_api_key"] = os.environ.get("MAILGUN_API_KEY", config_data.get("mailgun_api_key", ""))
            
            return Config(**config_data)
            
        except Exception as e:
            logger.critical(f"Failed to load configuration: {str(e)}")
            sys.exit(1)
    
    def setup(self) -> None:
        """Set up the required components."""
        try:
            # Initialize Anthropic client
            self.anthropic_client = anthropic.Anthropic(api_key=self.config.anthropic_api_key)
            
            # Initialize components
            self.fail2ban = Fail2BanHandler(self.config.fail2ban_jail)
            self.whois_parser = WHOISParser(self.anthropic_client, self.config.anthropic_model, self.config.whois_timeout)
            self.report_generator = AbuseReportGenerator(self.anthropic_client, self.config.anthropic_model, self.config.report_template)
            self.email_sender = EmailSender(
                self.config.mailgun_api_key,
                self.config.mailgun_domain,
                self.config.mailgun_from_email,
                self.config.mailgun_reply_to
            )
            self.ip_db = IPDatabase(self.config.database_file)
            
            # Prepare excluded IPs list as network objects
            self.excluded_networks = []
            for ip_range in self.config.exclude_ips:
                try:
                    self.excluded_networks.append(ipaddress.ip_network(ip_range, strict=False))
                except ValueError as e:
                    logger.warning(f"Invalid IP range in exclusions: {ip_range} - {str(e)}")
            
            logger.info("SSH Abuse Reporter initialized successfully")
            
        except Exception as e:
            logger.critical(f"Failed to initialize SSH Abuse Reporter: {str(e)}")
            sys.exit(1)
    
    def is_excluded_ip(self, ip: str) -> bool:
        """Check if an IP is in the excluded list or is a private/reserved address."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check if IP is private or reserved
            if ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_loopback:
                return True
            
            # Check if IP is in excluded networks
            for network in self.excluded_networks:
                if ip_obj in network:
                    return True
            
            return False
            
        except ValueError:
            logger.warning(f"Invalid IP address: {ip}")
            return True  # Exclude invalid IPs
    
    def get_server_info(self, ip: str) -> Dict[str, Any]:
        """Get information about the server and attack."""
        # Get historical data if available
        historical_data = self.fail2ban.get_historical_banned_ips()
        
        # Default info
        server_info = {
            "hostname": socket.gethostname(),
            "detection_time": datetime.now().isoformat(),
            "attempt_count": "unknown",
            "source_ip": ip,
            "first_seen": None,
            "ban_count": 0,
            "is_repeat_offender": False
        }
        
        # Enhance with historical data if available
        if ip in historical_data and historical_data[ip]:
            ban_timestamps = historical_data[ip]
            
            # Sort timestamps chronologically
            ban_timestamps.sort()
            
            server_info["ban_count"] = len(ban_timestamps)
            server_info["first_seen"] = ban_timestamps[0].isoformat()
            server_info["latest_ban"] = ban_timestamps[-1].isoformat()
            server_info["is_repeat_offender"] = len(ban_timestamps) > 1
            
            # If banned multiple times, calculate average time between bans
            if len(ban_timestamps) > 1:
                time_diffs = []
                for i in range(1, len(ban_timestamps)):
                    diff = (ban_timestamps[i] - ban_timestamps[i-1]).total_seconds() / 3600  # hours
                    time_diffs.append(diff)
                    
                server_info["avg_hours_between_bans"] = sum(time_diffs) / len(time_diffs)
        
        return server_info
    
    def process_banned_ip(self, ip: str) -> None:
        """Process a single banned IP address."""
        if self.is_excluded_ip(ip):
            logger.info(f"Skipping excluded IP: {ip}")
            return
        
        # Check if this IP can be reported based on frequency settings
        if not self.ip_db.can_report_ip(ip, self.config.report_frequency_hours):
            logger.info(f"Skipping recently reported IP: {ip}")
            return
        
        # Get WHOIS data
        whois_data = self.whois_parser.get_whois_data(ip)
        if not whois_data:
            logger.warning(f"No WHOIS data found for IP: {ip}")
            return
        
        # Extract abuse contact
        abuse_email, whois_info = self.whois_parser.extract_abuse_contact(whois_data, ip)
        if not abuse_email:
            logger.warning(f"No abuse contact found for IP: {ip}")
            return
        
        # Generate the report
        server_info = self.get_server_info(ip)
        report = self.report_generator.generate_report(ip, whois_info, server_info)
        
        # Create email subject
        subject = f"SSH Brute Force Report: {ip} from {server_info['hostname']}"
        
        # Send the report
        success, response = self.email_sender.send_report(abuse_email, subject, report, ip)
        
        if success:
            # Record the successful report
            report_info = {
                "abuse_email": abuse_email,
                "whois_info": whois_info,
                "server_info": server_info,
                "response": response
            }
            self.ip_db.add_reported_ip(ip, report_info)
            logger.info(f"Successfully reported IP {ip} to {abuse_email}")
        else:
            logger.error(f"Failed to report IP {ip} to {abuse_email}")
    
    def run(self) -> None:
        """Run the abuse reporting process."""
        logger.info("Starting SSH abuse reporting process")
        
        # Check if we've hit the daily limit
        report_count = self.ip_db.get_report_count_today()
        if report_count >= self.config.max_reports_per_day:
            logger.warning(f"Daily report limit reached ({report_count}/{self.config.max_reports_per_day})")
            return
        
        # Get currently banned IPs
        current_banned_ips = self.fail2ban.get_banned_ips()
        logger.info(f"Found {len(current_banned_ips)} currently banned IPs")
        
        # Get historical banned IPs
        historical_banned_ips = self.fail2ban.get_historical_banned_ips(days_back=self.config.history_days)
        logger.info(f"Found {len(historical_banned_ips)} historically banned IPs from the last {self.config.history_days} days")
        
        # Combine current and historical IPs (prioritize current)
        all_ips = set(current_banned_ips)
        all_ips.update(historical_banned_ips.keys())
        logger.info(f"Processing {len(all_ips)} total unique IPs")
        
        # Process each banned IP
        for ip in all_ips:
            # Check if we've hit the daily limit during processing
            if self.ip_db.get_report_count_today() >= self.config.max_reports_per_day:
                logger.warning("Daily report limit reached during processing")
                break
                
            self.process_banned_ip(ip)
            # Add a small delay between processing IPs to avoid rate limits
            time.sleep(1)
        
        logger.info("SSH abuse reporting process completed")


def main():
    """Main entry point for the script."""
    # Check command line arguments
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} config.json")
        sys.exit(1)
    
    config_file = sys.argv[1]
    
    try:
        # Initialize and run the reporter
        reporter = SSHAbuseReporter(config_file)
        reporter.run()
    except KeyboardInterrupt:
        logger.info("Process interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Unexpected error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
