import queue
import socket
import json
import threading
import time
import sys

from engines import (
    abuseipdb, virustotal, ipinfo, reverse_dns, google_safe_browsing,
    microsoft_defender_for_endpoint, spur_us_free, shodan, phishtank, abusix, rdap, threatfox, google, github, ioc_one, ipquery
)

from models.analysis_result import AnalysisResult
from utils.database import save_analysis_result, get_analysis_result
from utils.utils import is_bogon

# Constants
SECRETS_FILE = 'secrets.json'
TOR_PROXY = 'socks5h://127.0.0.1:9050'
TOR_PORT = 9051

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

def perform_analysis(app, observables, selected_engines, analysis_id):
    """Perform analysis on the given observables using the selected engines."""
    with app.app_context():
        start_time = time.time()

        # Store analysis metadata in the database
        analysis_result = AnalysisResult(
            id=analysis_id,
            results=[],
            start_time=start_time,
            end_time=None,
            start_time_string=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time)),
            end_time_string="",
            analysis_duration_string="",
            analysis_duration=0,
            selected_engines=selected_engines,
            in_progress=True
        )
        save_analysis_result(analysis_result)

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
        update_analysis_metadata(analysis_id, start_time, selected_engines, results)

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

    # 1. Check if IP is private
    if observable["type"] in ["IPv4", "IPv6"] and is_bogon(observable["value"]):
        observable["type"] = "BOGON"

    if "ioc_one_html" in selected_engines and observable["type"] in ["MD5", "SHA1", "SHA256", "URL", "FQDN", "IPv4", "IPv6"]:
        result['ioc_one_html'] = ioc_one.query_ioc_one_html(observable["value"], PROXIES)

    if "ioc_one_pdf" in selected_engines and observable["type"] in ["MD5", "SHA1", "SHA256", "URL", "FQDN", "IPv4", "IPv6"]:
        result['ioc_one_pdf'] = ioc_one.query_ioc_one_pdf(observable["value"], PROXIES)

    if "google" in selected_engines and observable["type"] in ["MD5", "SHA1", "SHA256", "URL", "FQDN", "IPv4", "IPv6"]:
        result['google'] = google.query_google(observable["value"], PROXIES)

    if "github" in selected_engines and observable["type"] in ["MD5", "SHA1", "SHA256", "URL", "FQDN", "IPv4", "IPv6"]:
        result['github'] = github.query_github(observable["value"], PROXIES)

    if "rdap" in selected_engines and observable["type"] in ["FQDN", "URL"]:
        result['rdap'] = rdap.query_openrdap(observable["value"], observable["type"], PROXIES)

    if "mde" in selected_engines and observable["type"] in ["MD5", "SHA1", "SHA256", "URL", "FQDN", "IPv4", "IPv6", "BOGON"]:
        result['mde'] = microsoft_defender_for_endpoint.query_microsoft_defender_for_endpoint(
            observable["value"], observable["type"], secrets["mde_tenant_id"], secrets["mde_client_id"], secrets["mde_client_secret"], PROXIES
        )
    
    if "threatfox" in selected_engines and observable["type"] in ["URL", "FQDN", "IPv4", "IPv6"]:
        result['threatfox'] = threatfox.query_threatfox(observable["value"], observable["type"], PROXIES)

    if "virustotal" in selected_engines and observable["type"] in ["MD5", "SHA1", "SHA256", "URL", "FQDN", "IPv4", "IPv6"]:
        result['virustotal'] = virustotal.query_virustotal(observable["value"], observable["type"], secrets["virustotal"], PROXIES)

    if "google_safe_browsing" in selected_engines and observable["type"] in ["URL", "FQDN", "IPv4", "IPv6"]:
        result['google_safe_browsing'] = google_safe_browsing.query_google_safe_browsing(observable["value"], observable["type"], secrets["google_safe_browsing"], PROXIES)

    if "phishtank" in selected_engines and observable["type"] in ["FQDN", "URL"]:
        result['phishtank'] = phishtank.query_phishtank(observable["value"], observable["type"], PROXIES)
    
    # 2. Reverse DNS if possible, change observable type to IP if possible
    if "reverse_dns" in selected_engines and observable["type"] in ["IPv4", "IPv6", "FQDN", "URL", "BOGON"]:
        reverse_dns_result = reverse_dns.reverse_dns(observable["value"], observable["type"])
        result['reverse_dns'] = reverse_dns_result
        if reverse_dns_result:
            result['reversed_success'] = True
            if observable["type"] in ["FQDN", "URL"]:
                observable["type"] = "IPv4"
                observable["value"] = reverse_dns_result["reverse_dns"][0]

    if "ipquery" in selected_engines and observable["type"] in ["IPv4", "IPv6"]:
        result['ipquery'] = ipquery.query_ipquery(observable["value"], PROXIES)

    if "ipinfo" in selected_engines and observable["type"] in ["IPv4", "IPv6"]:
        result['ipinfo'] = ipinfo.query_ipinfo(observable["value"], secrets["ipinfo"], PROXIES)

    if "abuseipdb" in selected_engines and observable["type"] in ["IPv4", "IPv6"]:
        result['abuseipdb'] = abuseipdb.query_abuseipdb(observable["value"], secrets["abuseipdb"], PROXIES)

    if "spur" in selected_engines and observable["type"] in ["IPv4", "IPv6"]:
        result['spur'] = spur_us_free.get_spur(observable["value"], SPUR_PROXIES)

    if "shodan" in selected_engines and observable["type"] in ["IPv4", "IPv6"]:
        result['shodan'] = shodan.query_shodan(observable["value"], secrets["shodan"], PROXIES)

    if "abusix" in selected_engines and observable["type"] in ["IPv4", "IPv6"]:
        result['abusix'] = abusix.query_abusix(observable["value"])

    # print("Results: ", result, file=sys.stderr)
    return result

def collect_results_from_queue(result_queue, num_observables):
    """Collect results from the result queue."""
    results = [None] * num_observables
    while not result_queue.empty():
        index, result = result_queue.get()
        results[index] = result
    return results

def check_analysis_in_progress(analysis_id):
    """Check if the analysis is in progress."""
    analysis_result = get_analysis_result(analysis_id)
    return analysis_result.in_progress if analysis_result else False

def update_analysis_metadata(analysis_id, start_time, selected_engines, results):
    """Update the analysis metadata."""
    analysis_result = get_analysis_result(analysis_id)
    if analysis_result:
        end_time = time.time()
        analysis_result.end_time = end_time
        analysis_result.end_time_string = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time))
        analysis_result.analysis_duration = end_time - start_time
        analysis_result.analysis_duration_string = f"{int((end_time - start_time) // 60)} minutes, {(end_time - start_time) % 60:.2f} seconds"
        analysis_result.results = results
        analysis_result.in_progress = False
        save_analysis_result(analysis_result)
