import logging
import json
from datetime import datetime
import os

class SecurityLogger:
    """
    Logs security events to a file in a structured format.
    """
    def __init__(self, log_file):
        self.log_file = log_file
        
        # Setup specific logger for security events
        self.logger = logging.getLogger('SentinelShield')
        self.logger.setLevel(logging.INFO)
        
        # File handler
        handler = logging.FileHandler(self.log_file)
        formatter = logging.Formatter('%(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def log_event(self, event_data):
        """
        Logs a dictionary of event data.
        :param event_data: dict
        """
        event_data['timestamp'] = datetime.now().isoformat()
        
        # Format as JSON for potential machine parsing but also readable
        log_entry = json.dumps(event_data)
        self.logger.info(log_entry)
