import time
from collections import defaultdict

class BehaviorMonitor:
    """
    Tracks request rates and flags abusive IPs.
    """
    def __init__(self, time_window=60, max_requests=100):
        """
        :param time_window: Time in seconds to track requests
        :param max_requests: Max allowed requests per time window
        """
        self.time_window = time_window
        self.max_requests = max_requests
        # Stores timestamps of requests per IP: {ip: [ts1, ts2, ...]}
        self.request_history = defaultdict(list)
        # Blocked IPs with expiry time: {ip: expiry_timestamp}
        self.blocked_ips = {}
        self.block_duration = 300 # Block for 5 minutes

    def check_ip(self, ip_address):
        """
        Checks if an IP is behaving abusively.
        :return: dict {'status': 'ALLOW'|'BLOCK', 'reason': str}
        """
        current_time = time.time()
        
        # Check if already blocked
        if ip_address in self.blocked_ips:
            if current_time < self.blocked_ips[ip_address]:
                return {'status': 'BLOCK', 'reason': 'IP temporarily blocked due to rate limiting'}
            else:
                del self.blocked_ips[ip_address] # Unblock

        # Record new request
        self.request_history[ip_address].append(current_time)
        
        # Cleanup old requests outside the window
        self.request_history[ip_address] = [
            t for t in self.request_history[ip_address] 
            if t > current_time - self.time_window
        ]
        
        # Check rate limit
        request_count = len(self.request_history[ip_address])
        if request_count > self.max_requests:
            self.blocked_ips[ip_address] = current_time + self.block_duration
            return {'status': 'BLOCK', 'reason': f'Rate limit exceeded ({request_count}/{self.time_window}s)'}
            
        return {'status': 'ALLOW', 'reason': 'Normal behavior'}
