import pandas as pd
import threading
import time
import os
from flask import send_file

def prepare_row(result, analysis_metadata):
    rev_dns_data = result.get("reverse_dns", {})
    ipinfo_data = result.get("ipinfo", {})
    abuseipdb_data = result.get("abuseipdb", {})

    row = {
        "observable": result.get("observable"),
        "type": result.get("type"),
        "rev_dns": result.get("reversed_success") if rev_dns_data else None,
        "dns_lookup": rev_dns_data.get("reverse_dns") if rev_dns_data else None,
        "ipinfo_cn": ipinfo_data.get("country_code") if ipinfo_data else None,
        "ipinfo_country": ipinfo_data.get("country_name") if ipinfo_data else None,
        "ipinfo_geo": ipinfo_data.get("geolocation") if ipinfo_data else None,
        "ipinfo_asn": ipinfo_data.get("asn").split(' ', 1)[0] if ipinfo_data.get("asn") else None,
        "ipinfo_org": ipinfo_data.get("asn").split(' ', 1)[1] if ipinfo_data.get("asn") else None,
        "a_ipdb_reports": abuseipdb_data.get("reports") if abuseipdb_data else None,
        "a_ipdb_risk": abuseipdb_data.get("risk_score") if abuseipdb_data else None
    }

    if "virustotal" in analysis_metadata["selected_engines"]:
        virustotal_data = result.get("virustotal", {})
        row["vt_detect"] = virustotal_data.get("detection_ratio") if virustotal_data else None
        row["vt_nb_detect"] = virustotal_data.get("total_malicious") if virustotal_data else None
        row["vt_community"] = virustotal_data.get("community_score") if virustotal_data else None

    if "ip_quality_score" in analysis_metadata["selected_engines"]:
        ip_quality_score_data = result.get("ip_quality_score", {})
        row["ipqs_score"] = ip_quality_score_data.get("fraud_score") if ip_quality_score_data else None
        row["ipqs_proxy"] = ip_quality_score_data.get("proxy") if ip_quality_score_data else None
        row["ipqs_vpn"] = ip_quality_score_data.get("vpn") if ip_quality_score_data else None
        row["ipqs_tor"] = ip_quality_score_data.get("tor") if ip_quality_score_data else None
        row["ipqs_isp"] = ip_quality_score_data.get("ISP") if ip_quality_score_data else None
        row["ipqs_organization"] = ip_quality_score_data.get("organization") if ip_quality_score_data else None

    if "spur" in analysis_metadata["selected_engines"]:
        spur_data = result.get("spur", {})
        row["spur_us_anon"] = spur_data.get("tunnels") if spur_data else None

    if "google_safe_browsing" in analysis_metadata["selected_engines"]:
        google_safe_browsing_data = result.get("google_safe_browsing", {})
        row["gsb_threat"] = google_safe_browsing_data.get("threat_found") if google_safe_browsing_data else None

    if "shodan" in analysis_metadata["selected_engines"]:
        shodan_data = result.get("shodan", {})
        row["shodan_ports"] = shodan_data.get("ports") if shodan_data else None

    return row

def prepare_data_for_export(results, analysis_metadata):
    data = []
    for result in results:
        row = prepare_row(result, analysis_metadata)
        data.append(row)
    return data

def export_to_csv(data, timestamp):
    df = pd.DataFrame(data)
    csv_path = f'{timestamp}_analysis_result.csv'
    df.to_csv(csv_path, index=False, sep=';')
    response = send_file(csv_path, as_attachment=True)
    threading.Thread(target=lambda path: (time.sleep(10), os.remove(path)), args=(csv_path,)).start()
    return response

def export_to_excel(data, timestamp):
    df = pd.DataFrame(data)
    excel_path = f'{timestamp}_analysis_result.xlsx'
    with pd.ExcelWriter(excel_path, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Results')
        workbook = writer.book
        worksheet = writer.sheets['Results']
        (max_row, max_col) = df.shape
        worksheet.auto_filter.ref = worksheet.dimensions
        for col in worksheet.columns:
            max_length = 0
            column = col[0].column_letter
            for cell in col:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(str(cell.value))
                except:
                    pass
            adjusted_width = (max_length + 2)
            worksheet.column_dimensions[column].width = adjusted_width
    response = send_file(excel_path, as_attachment=True)
    threading.Thread(target=lambda path: (time.sleep(10), os.remove(path)), args=(excel_path,)).start()
    return response