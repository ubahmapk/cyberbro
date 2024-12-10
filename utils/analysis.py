import queue
import socket
import json
import threading
import time

from engines import (
    abuseipdb, virustotal, ipinfo, reverse_dns, google_safe_browsing,
    microsoft_defender_for_endpoint, ip_quality_score, spur_us_free, shodan, phishtank, abusix, rdap, threatfox
)

from utils.database import save_analysis_result_to_db

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

def check_analysis_in_progress(analysis_id):
    """Check if the analysis is in progress."""
    return analysis_in_progress_dict.get(analysis_id, False)

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
    save_analysis_result_to_db(analysis_id, analysis_metadata_dict, results_dict)
    cleanup_analysis_data(analysis_id)

def cleanup_analysis_data(analysis_id):
    """Clean up the analysis data from memory."""
    results_dict.pop(analysis_id, None)
    analysis_metadata_dict.pop(analysis_id, None)
    analysis_in_progress_dict.pop(analysis_id, None)