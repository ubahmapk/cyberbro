import logging
import queue
import threading
import time
from types import ModuleType

import flask

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

    """
    2. Reverse DNS if possible, change observable type to IP if possible.
    This is done to allow further enrichment with engines that require an only an IP address.
    The other engines at the top use the original observable type and value.
    e.g. IPquery only supports IPv4 and IPv6, so if the observable is a FQDN or URL,
    it will not be enriched by IPquery, but if it is a reverse DNS result, it will be enriched.
    This is a case of auto-pivoting, where the observable type is changed to IP.
    """

    """
    if "reverse_dns" in selected_engines and observable["type"] in reverse_dns.SUPPORTED_OBSERVABLE_TYPES:
        reverse_dns_result = reverse_dns.run_engine(observable["value"], observable["type"])
        result["reverse_dns"] = reverse_dns_result
        if reverse_dns_result:
            result["reversed_success"] = True
            if observable["type"] in ["FQDN", "URL"]:
                observable["type"] = "IPv4"
                observable["value"] = reverse_dns_result["reverse_dns"][0]
    """

    for engine in loaded_engines:
        if observable["type"] in engine.SUPPORTED_OBSERVABLE_TYPES:
            logger.debug(f"Running {engine.NAME} engine for observable: {observable['value']} ({observable['type']})")
            result[engine.NAME] = engine.run_engine(
                observable,
                PROXIES,
                SSL_VERIFY,
            )

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
