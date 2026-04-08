"""
logger.py
Handles logging of detected intrusions to a log file and standard output.
"""

import logging
from datetime import datetime
import colorama
from colorama import Fore, Style

# Initialize colorama for colored console output across OS environments
colorama.init(autoreset=True)

class IDSLogger:
    def __init__(self, log_file="ids_alerts.log"):
        self.log_file = log_file
        
        # Configure file logging
        self.file_logger = logging.getLogger("IDS_FILE_LOGGER")
        self.file_logger.setLevel(logging.INFO)
        file_handler = logging.FileHandler(self.log_file)
        
        # Logging format containing timestamp, severity, and message
        formatter = logging.Formatter('%(asctime)s - [%(levelname)s] - %(message)s')
        file_handler.setFormatter(formatter)
        self.file_logger.addHandler(file_handler)

    def log_alert(self, severity, src_ip, attack_type, details=""):
        """
        Logs the alert to the file and prominently displays it in the console.
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"Src IP: {src_ip} | Attack Type: {attack_type} | Details: {details}"
        
        # File Logging and determining display color
        if severity.upper() == "HIGH":
            self.file_logger.error(f"(HIGH) {log_message}")
            color = Fore.RED
        elif severity.upper() == "MEDIUM":
            self.file_logger.warning(f"(MEDIUM) {log_message}")
            color = Fore.YELLOW
        else: # LOW
            self.file_logger.info(f"(LOW) {log_message}")
            color = Fore.GREEN

        # Live Console Alert Print
        print(f"\r{color}[!] ALERT - [{severity.upper()}] - {timestamp} - {log_message}{Style.RESET_ALL}")
