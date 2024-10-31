from engines import abuseipdb, virustotal, ipinfo, spur_us, google_safe_browsing
from utils import *
from flask import Flask, request, render_template, send_file, redirect, url_for, jsonify
import pandas as pd
import threading

app = Flask(__name__)

# Variable globale pour stocker les résultats d'analyse
results = []
analysis_in_progress = False  # Variable pour suivre l'état de l'analyse

def perform_analysis(observables, selected_engines):
    global results, analysis_in_progress
    results = []  # Réinitialiser les résultats à chaque analyse
    analysis_in_progress = True

    for observable in observables:
        observable_type = identify_observable_type(observable.strip())
        result = {"observable": observable.strip(), "type": observable_type}
        
        # Vérifier chaque engine sélectionné
        if "virustotal" in selected_engines and observable_type in ["MD5", "SHA1", "SHA256", "URL", "FQDN", "IPv4", "IPv6"]:
            result['virustotal'] = virustotal.query_virustotal(observable.strip())

        if "ipinfo" in selected_engines and observable_type in ["IPv4", "IPv6"]:
            result['ipinfo'] = ipinfo.query_ipinfo(observable.strip())

        if "abuseipdb" in selected_engines and observable_type in ["IPv4", "IPv6"]:
            result['abuseipdb'] = abuseipdb.query_abuseipdb(observable.strip())

        if "spur" in selected_engines and observable_type in ["IPv4", "IPv6"]:
            result['spur'] = spur_us.process_ip_with_spur(observable.strip())

        if "google_safe_browsing" in selected_engines and observable_type in ["URL", "FQDN", "IPv4", "IPv6"]:
            result['google_safe_browsing'] = google_safe_browsing.query_google_safe_browsing(observable.strip())

        
        results.append(result)

    print("Résultats d'analyse:", results)
    analysis_in_progress = False  # Fin de l'analyse

# Route principale pour l'analyse
@app.route('/')
def index():
    return render_template('index.html', results=[])

@app.route('/analyze', methods=['POST'])
def analyze():
    observables = request.form.get("observables", "").splitlines()
    selected_engines = request.form.getlist("engines")

    # Lancer l'analyse dans un thread pour ne pas bloquer
    analysis_thread = threading.Thread(target=perform_analysis, args=(observables, selected_engines))
    analysis_thread.start()

    # Afficher la page d'attente
    return render_template('waiting.html'), 200  # Return 200 status for loading

@app.route('/results', methods=['GET'])
def show_results():
    return render_template('index.html', results=results)

@app.route('/is_analysis_complete', methods=['GET'])
def is_analysis_complete():
    return jsonify({'complete': not analysis_in_progress})

# Route pour exporter les résultats en CSV ou Excel
@app.route('/export')
def export():
    format = request.args.get('format')
    df = pd.DataFrame(results)  # Convertir les résultats en DataFrame

    if format == 'csv':
        csv_path = 'results.csv'
        df.to_csv(csv_path, index=False)
        return send_file(csv_path, as_attachment=True)

    elif format == 'excel':
        excel_path = 'results.xlsx'
        df.to_excel(excel_path, index=False)
        return send_file(excel_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
