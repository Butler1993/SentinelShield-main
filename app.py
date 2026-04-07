from flask import Flask, render_template, request, abort, Response
from config import Config
from core.decision_engine import DecisionEngine
import os

app = Flask(__name__)
app.config.from_object(Config)

# Ensure log directory exists (Must be before DecisionEngine/Logger init)
if not os.path.exists(os.path.dirname(app.config['LOG_FILE'])):
    os.makedirs(os.path.dirname(app.config['LOG_FILE']))

# Initialize Security Engine
start_time = None
decision_engine = DecisionEngine()

@app.before_request
def inspect_traffic():
    # Skip static files and dashboard from strict blocking (optional, but good for usability)
    if request.path.startswith('/static') or request.path.startswith('/dashboard'):
        return None

    action, reason = decision_engine.process_request(request)
    if action == 'BLOCK':
        return render_template('blocked.html', reason=reason), 403

@app.route('/')
def home():
    return render_template('index.html')

# Import and register dashboard blueprint
from dashboard.routes import dashboard_bp
app.register_blueprint(dashboard_bp, url_prefix='/dashboard')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, port=port, host='0.0.0.0')
