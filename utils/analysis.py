import logging
import queue
import threading
import time
from types import ModuleType

import flask

from engines import (
    abuseipdb,
    abusix,
    alienvault,
    criminalip,
    crowdstrike,
    crtsh,
    dfir_iris,
    github,
    google,
    google_dns,
    google_safe_browsing,
    hudsonrock,
    ioc_one_html,
    ioc_one_pdf,
    ipinfo,
    ipquery,
    microsoft_defender_for_endpoint,
    misp,
    opencti,
    phishtank,
    rdap,
    reverse_dns,
    shodan,
    spur_us,
    threatfox,
    urlscan,
    virustotal,
    webscout,
)
from models.analysis_result import AnalysisResult
from models.datatypes import ObservableMap, Proxies, Report
from utils.config import Secrets, get_config
from utils.database import get_analysis_result, save_analysis_result
from utils.utils import is_bogon

logger = logging.getLogger(__name__)

# Read the secrets from the config file
secrets: Secrets = get_config()

PROXIES: Proxies = Proxies({"http": secrets.proxy_url, "https": secrets.proxy_url})

SSL_VERIFY: bool = secrets.ssl_verify


def perform_analysis(
    app: flask.Flask, observables: list[ObservableMap], loaded_engines: list[ModuleType], analysis_id: str
) -> None:
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
            selected_engines=[engine.NAME for engine in loaded_engines],
            in_progress=True,
        )
        save_analysis_result(analysis_result)

        result_queue: queue.Queue[tuple[int, Report]] = queue.Queue()
        threads: list[threading.Thread] = [
            threading.Thread(
                target=analyze_observable,
                args=(observable, index, loaded_engines, result_queue),
            )
            for index, observable in enumerate(observables)
        ]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        results: list[Report] = collect_results_from_queue(result_queue, len(observables))
        update_analysis_metadata(analysis_id, start_time, results)


def analyze_observable(
    observable: ObservableMap,
    index: int,
    loaded_engines: list[ModuleType],
    result_queue: queue.Queue[tuple[int, Report]],
) -> None:
    result: Report = initialize_result(observable)
    result = perform_engine_queries(observable, loaded_engines, result)
    result_queue.put((index, result))


def initialize_result(observable: ObservableMap) -> Report:
    return Report(
        {
            "observable": observable["value"],
            "type": observable["type"],
            "reversed_success": False,
        }
    )


def perform_engine_queries(observable: ObservableMap, loaded_engines: list[ModuleType], result: Report) -> Report:
    # 1. Check if IP is private
    if observable["type"] in ["IPv4", "IPv6"] and is_bogon(observable["value"]):
        observable["type"] = "BOGON"
    """
    The chrome_extension engine retrieves the name of a Chrome or Edge extension
    using its ID. It is a default behavior for the CHROME_EXTENSION type, so the user doesn't need to select it
    explicitly in the engines list.

    The enrichment for this kind of observable is performed like the others engines at the top,
    the name is an exception.
    """

    for engine in loaded_engines:
        """
        We need a way to migrate engines over time to the control loop.

        Setting a MIGRATED flag in the engine module allows us to control which engines
        are executed in the new control loop and which ones are skipped.

        Engines that have been migrated should also be removed from the long if block above.
        """
        if not engine.MIGRATED:
            continue

        if observable["type"] in engine.SUPPORTED_OBSERVABLE_TYPES:
            logger.debug(f"Running {engine.NAME} engine for observable: {observable['value']} ({observable['type']})")
            result[engine.NAME] = engine.run_engine(
                observable,
                PROXIES,
                SSL_VERIFY,
            )

    """
    Temporary generation of selected engines list from loaded engines.
    For use during migration to dynamic loading
    """
    selected_engines: list[str] = [engine.NAME.lower() for engine in loaded_engines if not engine.MIGRATED]

    if "urlscan" in selected_engines and observable["type"] in urlscan.SUPPORTED_OBSERVABLE_TYPES:
        result["urlscan"] = urlscan.run_engine(observable["value"], observable["type"], PROXIES, SSL_VERIFY)

    if "crtsh" in selected_engines and observable["type"] in crtsh.SUPPORTED_OBSERVABLE_TYPES:
        result["crtsh"] = crtsh.run_engine(observable["value"], observable["type"], PROXIES, SSL_VERIFY)

    if "ioc_one_html" in selected_engines and observable["type"] in ioc_one_html.SUPPORTED_OBSERVABLE_TYPES:
        result["ioc_one_html"] = ioc_one_html.query_ioc_one_html(observable["value"], PROXIES, SSL_VERIFY)

    if "ioc_one_pdf" in selected_engines and observable["type"] in ioc_one_pdf.SUPPORTED_OBSERVABLE_TYPES:
        result["ioc_one_pdf"] = ioc_one_pdf.query_ioc_one_pdf(observable["value"], PROXIES, SSL_VERIFY)

    if "google" in selected_engines and observable["type"] in google.SUPPORTED_OBSERVABLE_TYPES:
        result["google"] = google.query_google(observable["value"], observable["type"], PROXIES, SSL_VERIFY)

    if "github" in selected_engines and observable["type"] in github.SUPPORTED_OBSERVABLE_TYPES:
        result["github"] = github.query_github(observable["value"], PROXIES, SSL_VERIFY)

    if "rdap" in selected_engines and observable["type"] in rdap.SUPPORTED_OBSERVABLE_TYPES:
        result["rdap"] = rdap.query_openrdap(observable["value"], observable["type"], PROXIES, SSL_VERIFY)

    if "mde" in selected_engines and observable["type"] in microsoft_defender_for_endpoint.SUPPORTED_OBSERVABLE_TYPES:
        result["mde"] = microsoft_defender_for_endpoint.query_microsoft_defender_for_endpoint(
            observable["value"],
            observable["type"],
            secrets.mde_tenant_id,
            secrets.mde_client_id,
            secrets.mde_client_secret,
            PROXIES,
            SSL_VERIFY,
        )

    if "crowdstrike" in selected_engines and observable["type"] in crowdstrike.SUPPORTED_OBSERVABLE_TYPES:
        result["crowdstrike"] = crowdstrike.query_crowdstrike(
            observable["value"],
            observable["type"],
            secrets.crowdstrike_client_id,
            secrets.crowdstrike_client_secret,
            secrets.crowdstrike_falcon_base_url,
            SSL_VERIFY,
            PROXIES,
        )

    if "opencti" in selected_engines and observable["type"] in opencti.SUPPORTED_OBSERVABLE_TYPES:
        result["opencti"] = opencti.query_opencti(
            observable["value"],
            secrets.opencti_api_key,
            secrets.opencti_url,
            PROXIES,
            SSL_VERIFY,
        )

    if "dfir_iris" in selected_engines and observable["type"] in dfir_iris.SUPPORTED_OBSERVABLE_TYPES:
        result["dfir_iris"] = dfir_iris.query_dfir_iris(
            observable["value"],
            observable["type"],
            secrets.dfir_iris_api_key,
            secrets.dfir_iris_url,
            PROXIES,
            SSL_VERIFY,
        )

    if "threatfox" in selected_engines and observable["type"] in threatfox.SUPPORTED_OBSERVABLE_TYPES:
        result["threatfox"] = threatfox.query_threatfox(
            observable["value"], observable["type"], secrets.threatfox, PROXIES, SSL_VERIFY
        )

    if "virustotal" in selected_engines and observable["type"] in virustotal.SUPPORTED_OBSERVABLE_TYPES:
        result["virustotal"] = virustotal.query_virustotal(
            observable["value"],
            observable["type"],
            secrets.virustotal,
            PROXIES,
            SSL_VERIFY,
        )

    if "alienvault" in selected_engines and observable["type"] in alienvault.SUPPORTED_OBSERVABLE_TYPES:
        result["alienvault"] = alienvault.run_engine(
            observable,
            PROXIES,
            SSL_VERIFY,
        )

    if "misp" in selected_engines and observable["type"] in misp.SUPPORTED_OBSERVABLE_TYPES:
        result["misp"] = misp.query_misp(
            observable["value"],
            observable["type"],
            PROXIES,
            SSL_VERIFY,
            secrets.misp_api_key,
            secrets.misp_url,
        )

    if (
        "google_safe_browsing" in selected_engines
        and observable["type"] in google_safe_browsing.SUPPORTED_OBSERVABLE_TYPES
    ):
        result["google_safe_browsing"] = google_safe_browsing.query_google_safe_browsing(
            observable["value"],
            observable["type"],
            secrets.google_safe_browsing,
            PROXIES,
            SSL_VERIFY,
        )

    if "phishtank" in selected_engines and observable["type"] in phishtank.SUPPORTED_OBSERVABLE_TYPES:
        result["phishtank"] = phishtank.query_phishtank(observable["value"], observable["type"], PROXIES, SSL_VERIFY)

    if "criminalip" in selected_engines and observable["type"] in criminalip.SUPPORTED_OBSERVABLE_TYPES:
        result["criminalip"] = criminalip.run_criminal_ip_analysis(
            observable["value"],
            PROXIES,
            SSL_VERIFY,
        )

    if "hudsonrock" in selected_engines and observable["type"] in hudsonrock.SUPPORTED_OBSERVABLE_TYPES:
        result["hudsonrock"] = hudsonrock.query_hudsonrock(observable["value"], observable["type"], PROXIES, SSL_VERIFY)

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
        reverse_dns_result = reverse_dns.run_engine(observable["value"], observable["type"])
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
        result["abuseipdb"] = abuseipdb.query_abuseipdb(observable["value"], secrets.abuseipdb, PROXIES, SSL_VERIFY)

    if "spur" in selected_engines and observable["type"] in spur_us.SUPPORTED_OBSERVABLE_TYPES:
        result["spur"] = spur_us.query_spur_us(observable["value"], PROXIES, SSL_VERIFY, secrets.spur_us)

    if "webscout" in selected_engines and observable["type"] in webscout.SUPPORTED_OBSERVABLE_TYPES:
        result["webscout"] = webscout.query_webscout(observable["value"], secrets.webscout, PROXIES, SSL_VERIFY)

    if "shodan" in selected_engines and observable["type"] in shodan.SUPPORTED_OBSERVABLE_TYPES:
        result["shodan"] = shodan.query_shodan(observable["value"], secrets.shodan, PROXIES, SSL_VERIFY)

    if "abusix" in selected_engines and observable["type"] in abusix.SUPPORTED_OBSERVABLE_TYPES:
        result["abusix"] = abusix.query_abusix(observable["value"])

    # print("Results: ", result, file=sys.stderr)
    return result


def collect_results_from_queue(result_queue: queue.Queue[tuple[int, Report]], num_observables: int) -> list[Report]:
    results: list[Report] = []
    # results: list[Report] = [Report * num_observables]
    while not result_queue.empty():
        index, result = result_queue.get()
        results[index] = result
    return results


def check_analysis_in_progress(analysis_id: str) -> bool:
    analysis_result: AnalysisResult | None = get_analysis_result(analysis_id)
    return analysis_result.in_progress if analysis_result else False


def update_analysis_metadata(analysis_id: str, start_time: float, results: list[Report]) -> None:
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
