from engines import abuseipdb, virustotal, ipinfo, spur_us, reverse_dns, google_safe_browsing
from utils import *
from flask import Flask, request, render_template, send_file, jsonify
import pandas as pd
import threading
import time
import queue

app = Flask(__name__)

# Global variable to store analysis results
results = []
analysis_in_progress = False  # Variable to track the state of the analysis
analysis_metadata = {}

def perform_analysis(observables, selected_engines):
    start_time = time.time()
    global results, analysis_in_progress, analysis_metadata
    results = []  # Reset results for each analysis
    analysis_in_progress = True

    result_queue = queue.Queue()

    def analyze_observable(observable, observable_type, index):
        result = {"observable": observable.strip(), "type": observable_type}
        result['reversed_success'] = False

        if "virustotal" in selected_engines and observable_type in ["MD5", "SHA1", "SHA256", "URL", "FQDN", "IPv4", "IPv6"]:
            result['virustotal'] = virustotal.query_virustotal(observable.strip())

        if "google_safe_browsing" in selected_engines and observable_type in ["URL", "FQDN", "IPv4", "IPv6"]:
            result['google_safe_browsing'] = google_safe_browsing.query_google_safe_browsing(observable.strip())

        if "reverse_dns" in selected_engines and observable_type in ["IPv4", "IPv6", "FQDN"]:
            result['reverse_dns'] = reverse_dns.reverse_dns(observable.strip())
            if observable_type == "FQDN" and result['reverse_dns'] is not None:
                result['reversed_success'] = True
                observable_type = "IPv4"
                observable = result["reverse_dns"]["reverse_dns"][-1]

        if "ipinfo" in selected_engines and observable_type in ["IPv4", "IPv6"]:
            result['ipinfo'] = ipinfo.query_ipinfo(observable.strip())

        if "abuseipdb" in selected_engines and observable_type in ["IPv4", "IPv6"]:
            result['abuseipdb'] = abuseipdb.query_abuseipdb(observable.strip())

        if "spur" in selected_engines and observable_type in ["IPv4", "IPv6"]:
            result['spur'] = spur_us.process_ip_with_spur(observable.strip())

        result_queue.put((index, result))

    threads = []
    for index, observable in enumerate(observables):
        observable_type = identify_observable_type(observable.strip())
        thread = threading.Thread(target=analyze_observable, args=(observable, observable_type, index))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # Collect results from the queue and sort by index
    results = [None] * len(observables)
    while not result_queue.empty():
        index, result = result_queue.get()
        results[index] = result

    end_time = time.time()
    
    start_time_string = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time))
    end_time_string = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time))

    analysis_duration = end_time - start_time
    # convert analysis duration to minutes and seconds
    analysis_duration_string = f"{int(analysis_duration // 60)} minutes, {analysis_duration % 60:.2f} seconds"
    
    analysis_metadata = {"start_time": start_time, "end_time": end_time, "start_time_string": start_time_string, "end_time_string": end_time_string ,"analysis_duration_string": analysis_duration_string, "analysis_duration": analysis_duration}
    analysis_in_progress = False  # End of analysis
    # Existing code to perform analysis
    print("Analysis results:", results)
    print("Analysis metadata:", analysis_metadata)
    print(f"Analysis took {analysis_metadata['analysis_duration_string']}")

# Main route for analysis
@app.route('/')
def index():
    return render_template('index.html', results=[])

@app.route('/analyze', methods=['POST'])
def analyze():
    observables = [obs for obs in request.form.get("observables", "").splitlines() if obs.strip()]
    selected_engines = request.form.getlist("engines")

    # Start analysis in a thread to avoid blocking
    analysis_thread = threading.Thread(target=perform_analysis, args=(observables, selected_engines))
    analysis_thread.start()

    # Display the waiting page
    return render_template('waiting.html'), 200  # Return 200 status for loading

@app.route('/results', methods=['GET'])
def show_results():
    return render_template('index.html', results=results, analysis_metadata=analysis_metadata)

@app.route('/is_analysis_complete', methods=['GET'])
def is_analysis_complete():
    return jsonify({'complete': not analysis_in_progress})

# Route to export results in CSV or Excel
@app.route('/export')
def export():
    format = request.args.get('format')
    df = pd.DataFrame(results)  # Convert results to DataFrame

    if format == 'csv':
        csv_path = 'results.csv'
        df.to_csv(csv_path, index=False)
        return send_file(csv_path, as_attachment=True)

    elif format == 'excel':
        excel_path = 'results.xlsx'
        df.to_excel(excel_path, index=False)
        return send_file(excel_path, as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
