import os
import json
import time
import uuid
import queue
import socket
import threading
import pandas as pd
from flask import Flask, request, render_template, send_file, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

from engines import (
    abuseipdb, virustotal, ipinfo, reverse_dns, google_safe_browsing,
    microsoft_defender_for_endpoint, ip_quality_score, spur_us_free, shodan, phishtank, abusix
)
from utils.utils import extract_observables, refang_text
from utils.export import prepare_data_for_export, export_to_csv, export_to_excel

app = Flask(__name__)

# Configure database
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Ensure the data directory exists
DATA_DIR = os.path.join(BASE_DIR, 'data')
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Update the database URI to use the data directory
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(DATA_DIR, 'results.db')}"

db = SQLAlchemy(app)

# Define the AnalysisResult model
class AnalysisResult(db.Model):
    id = db.Column(db.String, primary_key=True)
    results = db.Column(db.JSON, nullable=False)
    start_time = db.Column(db.Float, nullable=False)
    end_time = db.Column(db.Float, nullable=False)
    start_time_string = db.Column(db.String, nullable=False)
    end_time_string = db.Column(db.String, nullable=False)
    analysis_duration_string = db.Column(db.String, nullable=False)
    analysis_duration = db.Column(db.Float, nullable=False)
    selected_engines = db.Column(db.JSON, nullable=False)

# Create the database tables if they do not exist
with app.app_context():
    db.create_all()

# Constants
SECRETS_FILE = 'secrets.json'
TOR_PROXY = 'socks5h://127.0.0.1:9050'
TOR_PORT = 9051

# Global variables
results_dict = {}
analysis_metadata_dict = {}
analysis_in_progress_dict = {}

def read_secrets():
    """Read secrets from the secrets.json file."""
    with open(SECRETS_FILE) as f:
        return json.load(f)

secrets = read_secrets()
PROXIES = {"http": secrets["proxy_url"], "https": secrets["proxy_url"]}

def is_tor_running():
    """Check if Tor is running."""
    try:
        with socket.create_connection(("127.0.0.1", TOR_PORT), timeout=2):
            return True
    except socket.error:
        return False

TOR_RUNNING = is_tor_running()
SPUR_PROXIES = {'http': TOR_PROXY, 'https': TOR_PROXY} if TOR_RUNNING else PROXIES

def perform_analysis(observables, selected_engines, analysis_id):
    """Perform analysis on the given observables using the selected engines."""
    start_time = time.time()
    results_dict[analysis_id] = []
    analysis_in_progress_dict[analysis_id] = True

    result_queue = queue.Queue()
    threads = [
        threading.Thread(target=analyze_observable, args=(observable, index, selected_engines, result_queue))
        for index, observable in enumerate(observables)
    ]

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    results = collect_results_from_queue(result_queue, len(observables))
    update_analysis_metadata(analysis_id, start_time, selected_engines)
    results_dict[analysis_id] = results
    analysis_in_progress_dict[analysis_id] = False

def analyze_observable(observable, index, selected_engines, result_queue):
    """Analyze a single observable."""
    result = initialize_result(observable)
    result = perform_engine_queries(observable, selected_engines, result)
    result_queue.put((index, result))

def initialize_result(observable):
    """Initialize the result dictionary for an observable."""
    return {"observable": observable["value"], "type": observable["type"], 'reversed_success': False}

def perform_engine_queries(observable, selected_engines, result):
    """Perform queries to the selected engines."""
    if "ipinfo" in selected_engines and observable["type"] in ["IPv4", "IPv6"]:
        result['ipinfo'] = ipinfo.query_ipinfo(observable["value"], secrets["ipinfo"], PROXIES)
        if result['ipinfo']['asn'] == "BOGON":
            observable["type"] = "BOGON"

    if "mde" in selected_engines and observable["type"] in ["MD5", "SHA1", "SHA256", "URL", "FQDN", "IPv4", "IPv6", "BOGON"]:
        result['mde'] = microsoft_defender_for_endpoint.query_microsoft_defender_for_endpoint(
            observable["value"], observable["type"], secrets["mde_tenant_id"], secrets["mde_client_id"], secrets["mde_client_secret"], PROXIES
        )

    if "virustotal" in selected_engines and observable["type"] in ["MD5", "SHA1", "SHA256", "URL", "FQDN", "IPv4", "IPv6"]:
        result['virustotal'] = virustotal.query_virustotal(observable["value"], observable["type"], secrets["virustotal"], PROXIES)

    if "google_safe_browsing" in selected_engines and observable["type"] in ["URL", "FQDN", "IPv4", "IPv6"]:
        result['google_safe_browsing'] = google_safe_browsing.query_google_safe_browsing(observable["value"], observable["type"], secrets["google_safe_browsing"], PROXIES)

    if "phishtank" in selected_engines and observable["type"] in ["FQDN", "URL"]:
        result['phishtank'] = phishtank.query_phishtank(observable["value"], observable["type"], PROXIES)
    
    if "reverse_dns" in selected_engines and observable["type"] in ["IPv4", "IPv6", "FQDN", "URL", "BOGON"]:
        reverse_dns_result = reverse_dns.reverse_dns(observable["value"], observable["type"])
        result['reverse_dns'] = reverse_dns_result
        if reverse_dns_result:
            result['reversed_success'] = True
            if observable["type"] in ["FQDN", "URL"]:
                observable["type"] = "IPv4"
                observable["value"] = reverse_dns_result["reverse_dns"][0]

    if "ipinfo" in selected_engines and observable["type"] in ["IPv4", "IPv6"] and result['reversed_success']:
        result['ipinfo'] = ipinfo.query_ipinfo(observable["value"], secrets["ipinfo"], PROXIES)

    if "abuseipdb" in selected_engines and observable["type"] in ["IPv4", "IPv6"]:
        result['abuseipdb'] = abuseipdb.query_abuseipdb(observable["value"], secrets["abuseipdb"], PROXIES)

    if "spur" in selected_engines and observable["type"] in ["IPv4", "IPv6"]:
        result['spur'] = spur_us_free.get_spur(observable["value"], SPUR_PROXIES)

    if "ip_quality_score" in selected_engines and observable["type"] in ["IPv4", "IPv6"]:
        result['ip_quality_score'] = ip_quality_score.query_ip_quality_score(observable["value"], secrets["ip_quality_score"], PROXIES)

    if "shodan" in selected_engines and observable["type"] in ["IPv4", "IPv6"]:
        result['shodan'] = shodan.query_shodan(observable["value"], secrets["shodan"], PROXIES)

    if "abusix" in selected_engines and observable["type"] in ["IPv4", "IPv6"]:
        result['abusix'] = abusix.query_abusix(observable["value"])

    return result

def collect_results_from_queue(result_queue, num_observables):
    """Collect results from the result queue."""
    results = [None] * num_observables
    while not result_queue.empty():
        index, result = result_queue.get()
        results[index] = result
    return results

def update_analysis_metadata(analysis_id, start_time, selected_engines):
    """Update metadata for the analysis."""
    end_time = time.time()
    analysis_metadata_dict[analysis_id] = {
        "start_time": start_time,
        "end_time": end_time,
        "start_time_string": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time)),
        "end_time_string": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time)),
        "analysis_duration_string": f"{int((end_time - start_time) // 60)} minutes, {(end_time - start_time) % 60:.2f} seconds",
        "analysis_duration": end_time - start_time,
        "selected_engines": selected_engines
    }

def handle_analysis_completion(analysis_id):
    """Handle the completion of an analysis."""
    save_analysis_result_to_db(analysis_id)
    cleanup_analysis_data(analysis_id)

def cleanup_analysis_data(analysis_id):
    """Clean up the analysis data from memory."""
    results_dict.pop(analysis_id, None)
    analysis_metadata_dict.pop(analysis_id, None)
    analysis_in_progress_dict.pop(analysis_id, None)

def save_analysis_result_to_db(analysis_id):
    """Save the analysis result to the database."""
    analysis_result = create_analysis_result(analysis_id)
    db.session.add(analysis_result)
    db.session.commit()

def create_analysis_result(analysis_id):
    """Create an AnalysisResult object from the analysis data."""
    return AnalysisResult(
        id=analysis_id,
        results=results_dict.get(analysis_id, []),
        start_time=analysis_metadata_dict[analysis_id]["start_time"],
        end_time=analysis_metadata_dict[analysis_id]["end_time"],
        start_time_string=analysis_metadata_dict[analysis_id]["start_time_string"],
        end_time_string=analysis_metadata_dict[analysis_id]["end_time_string"],
        analysis_duration_string=analysis_metadata_dict[analysis_id]["analysis_duration_string"],
        analysis_duration=analysis_metadata_dict[analysis_id]["analysis_duration"],
        selected_engines=analysis_metadata_dict[analysis_id]["selected_engines"]
    )

@app.route('/')
def index():
    """Render the index page."""
    return render_template('index.html', results=[])

@app.route('/analyze', methods=['POST'])
def analyze():
    """Handle the analyze request."""
    form_data = refang_text(request.form.get("observables", ""))
    observables = extract_observables(form_data)
    selected_engines = request.form.getlist("engines")

    analysis_id = str(uuid.uuid4())
    threading.Thread(target=perform_analysis, args=(observables, selected_engines, analysis_id)).start()

    return render_template('waiting.html', analysis_id=analysis_id), 200

@app.route('/results/<analysis_id>', methods=['GET'])
def show_results(analysis_id):
    """Show the results of the analysis."""
    analysis_results = db.session.get(AnalysisResult, analysis_id)
    if analysis_results:
        return render_template('index.html', analysis_results=analysis_results)
    else:
        return render_template('404.html'), 404

@app.route('/is_analysis_complete/<analysis_id>', methods=['GET'])
def is_analysis_complete(analysis_id):
    """Check if the analysis is complete."""
    complete = not analysis_in_progress_dict.get(analysis_id, False)
    if complete:
        handle_analysis_completion(analysis_id)
    return jsonify({'complete': complete})

@app.route('/export/<analysis_id>')
def export(analysis_id):
    """Export the analysis results."""
    format = request.args.get('format')
    analysis_results = db.session.get(AnalysisResult, analysis_id)
    data = prepare_data_for_export(analysis_results)
    timestamp = time.strftime("%Y-%m-%d_%H_%M_%S", time.localtime())

    if format == 'csv':
        return export_to_csv(data, timestamp)
    elif format == 'excel':
        return export_to_excel(data, timestamp)

@app.route('/favicon.ico')
def favicon():
    """Serve the favicon."""
    return send_from_directory(os.path.join(app.root_path, 'images'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    """Handle 500 errors."""
    return render_template('500.html'), 500

# add a history page showing analysis results links
@app.route('/history')
def history():
    """Render the history page."""
    analysis_results = AnalysisResult.query.order_by(AnalysisResult.end_time.desc()).all()
    return render_template('history.html', analysis_results=analysis_results)

# add about page
@app.route('/about')
def about():
    """Render the about page."""
    return render_template('about.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
