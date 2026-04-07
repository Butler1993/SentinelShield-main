import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-for-sentinel-shield'
    if os.environ.get('VERCEL') or os.environ.get('NETLIFY'):
        LOG_FILE = os.path.join('/tmp', 'security.log')
    else:
        LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs', 'security.log')
    RULES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rules', 'attack_signatures.py')
