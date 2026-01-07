from .request_parser import RequestParser
from .signature_engine import SignatureEngine
from .behavior_monitor import BehaviorMonitor
from .logger import SecurityLogger
from config import Config

class DecisionEngine:
    """
    Main controller that orchestrates inspection and handles decisions.
    """
    def __init__(self):
        self.parser = RequestParser()
        self.signature_engine = SignatureEngine()
        self.behavior_monitor = BehaviorMonitor()
        self.logger = SecurityLogger(Config.LOG_FILE)

    def process_request(self, flask_request):
        """
        Analyzes the request and returns a decision.
        :param flask_request: Flask request object
        :return: (action, message) - action is 'ALLOW' or 'BLOCK'
        """
        # 1. Parse Request
        parsed_data = self.parser.parse(flask_request)
        ip = parsed_data['ip']

        # 2. Check Behavior (Rate Limiting)
        behavior_result = self.behavior_monitor.check_ip(ip)
        if behavior_result['status'] == 'BLOCK':
            self._log_event(parsed_data, 'Blocking IP', behavior_result['reason'], 'BLOCK')
            return 'BLOCK', behavior_result['reason']

        # 3. Check Signatures (Attack Detection)
        detections = self.signature_engine.analyze(parsed_data)
        if detections:
            # If any attack signature matches, BLOCK
            det_names = [d['rule_name'] for d in detections]
            reason = f"Attack Detected: {', '.join(det_names)}"
            self._log_event(parsed_data, 'Malicious Payload', reason, 'BLOCK', detections)
            return 'BLOCK', reason

        # 4. If all clear, ALLOW
        self._log_event(parsed_data, 'Traffic Inspection', 'Clean Request', 'ALLOW')
        return 'ALLOW', 'Request Authorized'

    def _log_event(self, parsed_data, category, reason, action, details=None):
        """
        Helper to log events.
        """
        log_data = {
            'action': action,
            'ip': parsed_data['ip'],
            'path': parsed_data['path'],
            'method': parsed_data['method'],
            'category': category,
            'reason': reason,
            'details': details or []
        }
        self.logger.log_event(log_data)
