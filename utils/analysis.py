import queue
import threading
import time

import flask

from engines import (
    abuseipdb,
    abusix,
    alienvault,
    chrome_extension,
    criminalip,
    crowdstrike,
    crtsh,
    github,
    google,
    google_dns,
    google_safe_browsing,
    hudsonrock,
    ioc_one,
    ipinfo,
    ipquery,
    microsoft_defender_for_endpoint,
    misp,
    opencti,
    phishtank,
    rdap,
    reverse_dns,
    shodan,
    spur_us_free,
    threatfox,
    urlscan,
    virustotal,
    webscout,
)
from models.analysis_result import AnalysisResult
from utils.config import Secrets, get_config
from utils.database import get_analysis_result, save_analysis_result
from utils.utils import is_bogon

# Read the secrets from the config file
secrets: Secrets = get_config()

PROXIES: dict[str, str] = {"http": secrets.proxy_url, "https": secrets.proxy_url}

SSL_VERIFY: bool = secrets.ssl_verify


def perform_analysis(app: flask.Flask, observables: list[dict], selected_engines: list[str], analysis_id: str) -> None:
    with app.app_context():
        start_time: float = time.time()

        # Store analysis metadata in the database
        analysis_result: AnalysisResult = AnalysisResult(
            id=analysis_id,
            results=[],
            start_time=start_time,
            end_time=None,
            start_time_string=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time)),
            end_time_string="",
            analysis_duration_string="",
            analysis_duration=0,
            selected_engines=selected_engines,
            in_progress=True,
        )
        save_analysis_result(analysis_result)

        result_queue: queue.Queue = queue.Queue()
        threads: list[threading.Thread] = [
            threading.Thread(
                target=analyze_observable,
                args=(observable, index, selected_engines, result_queue),
            )
            for index, observable in enumerate(observables)
        ]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        results: list = collect_results_from_queue(result_queue, len(observables))
        update_analysis_metadata(analysis_id, start_time, results)


def analyze_observable(observable: dict, index: int, selected_engines: list[str], result_queue: queue.Queue) -> None:
    result: dict[str, str | bool] = initialize_result(observable)
    result = perform_engine_queries(observable, selected_engines, result)
    result_queue.put((index, result))


def initialize_result(observable: dict) -> dict[str, str | bool]:
    return {
        "observable": observable["value"],
        "type": observable["type"],
        "reversed_success": False,
    }


def perform_engine_queries(observable: dict, selected_engines: list[str], result: dict) -> dict:
    # 1. Check if IP is private
    if observable["type"] in ["IPv4", "IPv6"] and is_bogon(observable["value"]):
        observable["type"] = "BOGON"

    if "urlscan" in selected_engines and observable["type"] in urlscan.SUPPORTED_OBSERVABLE_TYPES:
        result["urlscan"] = urlscan.run_engine(observable["value"], observable["type"], PROXIES, SSL_VERIFY)

    if "crtsh" in selected_engines and observable["type"] in crtsh.SUPPORTED_OBSERVABLE_TYPES:
        result["crtsh"] = crtsh.run_engine(observable["value"], observable["type"], PROXIES, SSL_VERIFY)

    if "ioc_one_html" in selected_engines and observable["type"] in ioc_one.SUPPORTED_OBSERVABLE_TYPES:
        result["ioc_one_html"] = ioc_one.query_ioc_one_html(observable["value"], PROXIES, SSL_VERIFY)

    if "ioc_one_pdf" in selected_engines and observable["type"] in ioc_one.SUPPORTED_OBSERVABLE_TYPES:
        result["ioc_one_pdf"] = ioc_one.query_ioc_one_pdf(observable["value"], PROXIES, SSL_VERIFY)

    if "google" in selected_engines and observable["type"] in google.SUPPORTED_OBSERVABLE_TYPES:
        result["google"] = google.run_engine(observable["value"], PROXIES, SSL_VERIFY)

    if "github" in selected_engines and observable["type"] in github.SUPPORTED_OBSERVABLE_TYPES:
        result["github"] = github.run_engine(observable["value"], PROXIES, SSL_VERIFY)

    if "rdap" in selected_engines and observable["type"] in rdap.SUPPORTED_OBSERVABLE_TYPES:
        result["rdap"] = rdap.run_engine(observable["value"], observable["type"], PROXIES, SSL_VERIFY)

    if "mde" in selected_engines and observable["type"] in microsoft_defender_for_endpoint.SUPPORTED_OBSERVABLE_TYPES:
        result["mde"] = microsoft_defender_for_endpoint.run_engine(
            observable["value"],
            observable["type"],
            PROXIES,
            SSL_VERIFY,
        )

    if "crowdstrike" in selected_engines and observable["type"] in crowdstrike.SUPPORTED_OBSERVABLE_TYPES:
        result["crowdstrike"] = crowdstrike.run_engine(
            observable["value"],
            observable["type"],
            PROXIES,
            SSL_VERIFY,
        )

    if "opencti" in selected_engines and observable["type"] in opencti.SUPPORTED_OBSERVABLE_TYPES:
        result["opencti"] = opencti.run_engine(
            observable["value"],
            PROXIES,
            SSL_VERIFY,
        )

    if "threatfox" in selected_engines and observable["type"] in threatfox.SUPPORTED_OBSERVABLE_TYPES:
        result["threatfox"] = threatfox.run_engine(observable["value"], observable["type"], PROXIES, SSL_VERIFY)

    if "virustotal" in selected_engines and observable["type"] in virustotal.SUPPORTED_OBSERVABLE_TYPES:
        result["virustotal"] = virustotal.run_engine(
            observable["value"],
            observable["type"],
            PROXIES,
            SSL_VERIFY,
        )

    if "alienvault" in selected_engines and observable["type"] in alienvault.SUPPORTED_OBSERVABLE_TYPES:
        result["alienvault"] = alienvault.run_engine(
            observable["value"],
            observable["type"],
            PROXIES,
            SSL_VERIFY,
        )

    if "misp" in selected_engines and observable["type"] in misp.SUPPORTED_OBSERVABLE_TYPES:
        result["misp"] = misp.run_engine(
            observable["value"],
            observable["type"],
            PROXIES,
            SSL_VERIFY,
        )

    if (
        "google_safe_browsing" in selected_engines
        and observable["type"] in google_safe_browsing.SUPPORTED_OBSERVABLE_TYPES
    ):
        result["google_safe_browsing"] = google_safe_browsing.run_engine(
            observable["value"],
            observable["type"],
            PROXIES,
            SSL_VERIFY,
        )

    if "phishtank" in selected_engines and observable["type"] in phishtank.SUPPORTED_OBSERVABLE_TYPES:
        result["phishtank"] = phishtank.run_engine(observable["value"], observable["type"], PROXIES, SSL_VERIFY)

    if "criminalip" in selected_engines and observable["type"] in criminalip.SUPPORTED_OBSERVABLE_TYPES:
        result["criminalip"] = criminalip.run_engine(
            observable["value"],
            PROXIES,
            SSL_VERIFY,
        )

    if "hudsonrock" in selected_engines and observable["type"] in hudsonrock.SUPPORTED_OBSERVABLE_TYPES:
        result["hudsonrock"] = hudsonrock.run_engine(observable["value"], observable["type"], PROXIES, SSL_VERIFY)

    if "google_dns" in selected_engines and observable["type"] in google_dns.SUPPORTED_OBSERVABLE_TYPES:
        result["google_dns"] = google_dns.query_google_dns(observable["value"], observable["type"], PROXIES, SSL_VERIFY)

    """
    2. Reverse DNS if possible, change observable type to IP if possible.
    This is done to allow further enrichment with engines that require an only an IP address.
    The other engines at the top use the original observable type and value.
    e.g. IPquery only supports IPv4 and IPv6, so if the observable is a FQDN or URL,
    it will not be enriched by IPquery, but if it is a reverse DNS result, it will be enriched.
    This is a case of auto-pivoting, where the observable type is changed to IP.
    """
    if "reverse_dns" in selected_engines and observable["type"] in reverse_dns.SUPPORTED_OBSERVABLE_TYPES:
        reverse_dns_result = reverse_dns.reverse_dns(observable["value"], observable["type"])
        result["reverse_dns"] = reverse_dns_result
        if reverse_dns_result:
            result["reversed_success"] = True
            if observable["type"] in ["FQDN", "URL"]:
                observable["type"] = "IPv4"
                observable["value"] = reverse_dns_result["reverse_dns"][0]

    if "ipquery" in selected_engines and observable["type"] in ipquery.SUPPORTED_OBSERVABLE_TYPES:
        result["ipquery"] = ipquery.query_ipquery(observable["value"], PROXIES, SSL_VERIFY)

    if "ipinfo" in selected_engines and observable["type"] in ipinfo.SUPPORTED_OBSERVABLE_TYPES:
        result["ipinfo"] = ipinfo.query_ipinfo(observable["value"], secrets.ipinfo, PROXIES, SSL_VERIFY)

    if "abuseipdb" in selected_engines and observable["type"] in abuseipdb.SUPPORTED_OBSERVABLE_TYPES:
        result["abuseipdb"] = abuseipdb.run_engine(observable["value"], PROXIES, SSL_VERIFY)

    if "spur" in selected_engines and observable["type"] in spur_us_free.SUPPORTED_OBSERVABLE_TYPES:
        result["spur"] = spur_us_free.get_spur(observable["value"], PROXIES, SSL_VERIFY)

    if "webscout" in selected_engines and observable["type"] in webscout.SUPPORTED_OBSERVABLE_TYPES:
        result["webscout"] = webscout.query_webscout(observable["value"], secrets.webscout, PROXIES, SSL_VERIFY)

    if "shodan" in selected_engines and observable["type"] in shodan.SUPPORTED_OBSERVABLE_TYPES:
        result["shodan"] = shodan.query_shodan(observable["value"], secrets.shodan, PROXIES, SSL_VERIFY)

    if "abusix" in selected_engines and observable["type"] in abusix.SUPPORTED_OBSERVABLE_TYPES:
        result["abusix"] = abusix.run_engine(observable["value"])

    """
    The chrome_extension engine retrieves the name of a Chrome or Edge extension
    using its ID. It is a default behavior for the CHROME_EXTENSION type, so the user doesn't need to select it
    explicitly in the engines list.

    The enrichment for this kind of observable is performed like the others engines at the top,
    the name is an exception.
    """
    if observable["type"] == "CHROME_EXTENSION":
        result["extension"] = chrome_extension.get_name_from_id(observable["value"], PROXIES, SSL_VERIFY)

    # print("Results: ", result, file=sys.stderr)
    return result


def collect_results_from_queue(result_queue: queue.Queue, num_observables: int) -> list:
    results = [None] * num_observables
    while not result_queue.empty():
        index, result = result_queue.get()
        results[index] = result
    return results


def check_analysis_in_progress(analysis_id: str) -> bool:
    analysis_result: AnalysisResult | None = get_analysis_result(analysis_id)
    return analysis_result.in_progress if analysis_result else False


def update_analysis_metadata(analysis_id: str, start_time: float, results: dict) -> None:
    analysis_result: AnalysisResult | None = get_analysis_result(analysis_id)
    if analysis_result:
        end_time = time.time()
        analysis_result.end_time = end_time
        analysis_result.end_time_string = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time))
        analysis_result.analysis_duration = end_time - start_time
        analysis_result.analysis_duration_string = (
            f"{int((end_time - start_time) // 60)} minutes, {(end_time - start_time) % 60:.2f} seconds"
        )
        analysis_result.results = results
        analysis_result.in_progress = False
        save_analysis_result(analysis_result)
