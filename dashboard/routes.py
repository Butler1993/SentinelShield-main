from flask import Blueprint, render_template
from config import Config
import os
import json
from collections import Counter

dashboard_bp = Blueprint('dashboard', __name__, template_folder='templates')

@dashboard_bp.route('/')
def dashboard_home():
    """
    Reads the security log and displays statistics.
    """
    stats = {
        'total_requests': 0,
        'blocked_requests': 0,
        'attacks_detected': 0,
        'attack_types': Counter(),
        'top_ips': Counter(),
        'recent_logs': [],
        'rate_limited_count': 0
    }

    log_file = Config.LOG_FILE
    
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
                # Reverse to get recent first
                for line in reversed(lines):
                    try:
                        entry = json.loads(line)
                        stats['total_requests'] += 1
                        stats['top_ips'][entry.get('ip', 'unknown')] += 1
                        
                        if entry.get('action') == 'BLOCK':
                            stats['blocked_requests'] += 1
                            
                            category = entry.get('category', 'Unknown')
                            if 'Traffic Inspection' not in category:
                                # It's an attack or rate limit
                                if 'Rate limit' in entry.get('reason', ''):
                                    stats['rate_limited_count'] += 1
                                elif 'Attack Detected' in entry.get('reason', ''):
                                    stats['attacks_detected'] += 1
                                    # Parse detailed attack types from reason if possible, 
                                    # or just use the rule name from details
                                    if entry.get('details'):
                                        for d in entry['details']:
                                            stats['attack_types'][d['rule_name']] += 1
                                    else:
                                         stats['attack_types'][entry.get('category')] += 1

                        # Keep last 50 logs for display
                        if len(stats['recent_logs']) < 50:
                            stats['recent_logs'].append(entry)

                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"Error reading log: {e}")

    return render_template('dashboard.html', stats=stats)
