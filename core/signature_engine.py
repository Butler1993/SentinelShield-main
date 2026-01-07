import sys
import os

# Add parent directory to path to allow importing rules
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from rules.attack_signatures import SIGNATURES

class SignatureEngine:
    """
    Checks request data against known attack signatures.
    """
    def __init__(self):
        self.signatures = SIGNATURES

    def analyze(self, request_data):
        """
        Scans request parts for malicious patterns.
        :param request_data: dict from RequestParser
        :return: list of detection dicts
        """
        detections = []
        
        # Fields to inspect
        fields_to_check = []
        
        # Add URL arguments values
        if request_data.get('args'):
            fields_to_check.extend(request_data['args'].values())
            
        # Add Body
        if request_data.get('body'):
            fields_to_check.append(str(request_data['body']))
            
        # Add Path (careful with false positives, but needed for traversal)
        if request_data.get('path'):
            fields_to_check.append(request_data['path'])

        # Check matched signatures
        for field_content in fields_to_check:
            if not isinstance(field_content, str):
                continue
                
            for rule in self.signatures:
                if rule['pattern'].search(field_content):
                    detections.append({
                        'category': rule['category'],
                        'rule_name': rule['name'],
                        'payload_snippet': field_content[:50] # Snippet for context
                    })
                    
        return detections
