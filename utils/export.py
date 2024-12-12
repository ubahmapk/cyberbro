import pandas as pd
import threading
import time
import os
from flask import send_file

def prepare_row(result, selected_engines):
    """
    Prepares a dictionary (row) with data extracted from the result dictionary based on the selected engines.
    Args:
        result (dict): A dictionary containing various data sources and their respective information.
        selected_engines (list): A list of strings representing the selected engines to include in the row.
    Returns:
        dict: A dictionary containing the prepared row with data from the result dictionary based on the selected engines.
    """
    rev_dns_data = result.get("reverse_dns", {})
    ipinfo_data = result.get("ipinfo", {})
    abuseipdb_data = result.get("abuseipdb", {})

    row = {
        "observable": result.get("observable"),
        "type": result.get("type")
    }

    if "reverse_dns" in selected_engines:
        row["rev_dns"] = result.get("reversed_success") if rev_dns_data else None
        row["dns_lookup"] = rev_dns_data.get("reverse_dns") if rev_dns_data else None

    if "ipinfo" in selected_engines:
        row["ipinfo_cn"] = ipinfo_data.get("country_code") if ipinfo_data else None
        row["ipinfo_country"] = ipinfo_data.get("country_name") if ipinfo_data else None
        row["ipinfo_geo"] = ipinfo_data.get("geolocation") if ipinfo_data else None
        row["ipinfo_asn"] = ipinfo_data.get("asn").split(' ', 1)[0] if ipinfo_data.get("asn") else None
        row["ipinfo_org"] = ipinfo_data.get("asn").split(' ', 1)[1] if ipinfo_data.get("asn") else None

    if "abuseipdb" in selected_engines:
        row["a_ipdb_reports"] = abuseipdb_data.get("reports") if abuseipdb_data else None
        row["a_ipdb_risk"] = abuseipdb_data.get("risk_score") if abuseipdb_data else None

    if "rdap" in selected_engines:
        rdap_data = result.get("rdap", {})
        row["rdap_abuse"] = rdap_data.get("abuse_contact") if rdap_data else None
        row["rdap_registrar"] = rdap_data.get("registrar") if rdap_data else None
        row["rdap_org"] = rdap_data.get("organization") if rdap_data else None
        row["rdap_registrant"] = rdap_data.get("registrant") if rdap_data else None
        row["rdap_registrant_email"] = rdap_data.get("registrant_email") if rdap_data else None
        row["rdap_ns"] = rdap_data.get("name_servers") if rdap_data else None
        row["rdap_creation"] = rdap_data.get("creation_date") if rdap_data else None
        row["rdap_expiration"] = rdap_data.get("expiration_date") if rdap_data else None
        row["rdap_update"] = rdap_data.get("update_date") if rdap_data else None

    if "abusix" in selected_engines:
        abusix_data = result.get("abusix", {})
        row["abusix_abuse"] = abusix_data.get("abuse") if abusix_data else None

    if "threatfox" in selected_engines:
        threatfox_data = result.get("threatfox", {})
        row["tf_count"] = threatfox_data.get("count") if threatfox_data else None
        row["tf_malware"] = threatfox_data.get("malware_printable") if threatfox_data else None

    if "virustotal" in selected_engines:
        virustotal_data = result.get("virustotal", {})
        row["vt_detect"] = virustotal_data.get("detection_ratio") if virustotal_data else None
        row["vt_nb_detect"] = virustotal_data.get("total_malicious") if virustotal_data else None
        row["vt_community"] = virustotal_data.get("community_score") if virustotal_data else None

    if "ip_quality_score" in selected_engines:
        ip_quality_score_data = result.get("ip_quality_score", {})
        row["ipqs_score"] = ip_quality_score_data.get("fraud_score") if ip_quality_score_data else None
        row["ipqs_proxy"] = ip_quality_score_data.get("proxy") if ip_quality_score_data else None
        row["ipqs_vpn"] = ip_quality_score_data.get("vpn") if ip_quality_score_data else None
        row["ipqs_tor"] = ip_quality_score_data.get("tor") if ip_quality_score_data else None
        row["ipqs_isp"] = ip_quality_score_data.get("ISP") if ip_quality_score_data else None
        row["ipqs_organization"] = ip_quality_score_data.get("organization") if ip_quality_score_data else None

    if "spur" in selected_engines:
        spur_data = result.get("spur", {})
        row["spur_us_anon"] = spur_data.get("tunnels") if spur_data else None

    if "google_safe_browsing" in selected_engines:
        google_safe_browsing_data = result.get("google_safe_browsing", {})
        row["gsb_threat"] = google_safe_browsing_data.get("threat_found") if google_safe_browsing_data else None

    if "shodan" in selected_engines:
        shodan_data = result.get("shodan", {})
        row["shodan_ports"] = shodan_data.get("ports") if shodan_data else None

    if "phishtank" in selected_engines:
        phishtank_data = result.get("phishtank", {})
        row["phishtank_in_db"] = phishtank_data.get("in_database") if phishtank_data else None
        row["phishtank_verified"] = phishtank_data.get("verified") if phishtank_data else None
        row["phishtank_valid"] = phishtank_data.get("valid") if phishtank_data else None

    return row

def prepare_data_for_export(analysis_results):
    """
    Prepares data for export based on the analysis results.

    Args:
        analysis_results (AnalysisResults): An object containing the results of the analysis and the selected engines.

    Returns:
        list: A list of rows, where each row is prepared based on the analysis results and selected engines.
    """
    data = []
    for result in analysis_results.results:
        row = prepare_row(result, analysis_results.selected_engines)
        data.append(row)
    return data

def export_to_csv(data, timestamp):
    """
    Exports the given data to a CSV file and sends it as an attachment.

    Args:
        data (list or dict): The data to be exported to CSV. It should be in a format that can be converted to a pandas DataFrame.
        timestamp (str): A timestamp string to be used in the CSV file name.

    Returns:
        Response: A Flask response object that sends the CSV file as an attachment.

    The CSV file is named using the provided timestamp and is deleted 10 seconds after being sent.
    """
    df = pd.DataFrame(data)
    csv_path = f'{timestamp}_analysis_result.csv'
    df.to_csv(csv_path, index=False, sep=';')
    response = send_file(csv_path, as_attachment=True)
    threading.Thread(target=lambda path: (time.sleep(10), os.remove(path)), args=(csv_path,)).start()
    return response

def export_to_excel(data, timestamp):
    """
    Exports the given data to an Excel file with a timestamp in the filename.

    Args:
        data (list of dict): The data to be exported, where each dictionary represents a row.
        timestamp (str): A string representing the timestamp to be included in the filename.

    Returns:
        Response: A Flask response object to send the file as an attachment.

    The function performs the following steps:
    1. Converts the data into a pandas DataFrame.
    2. Creates an Excel file with the given timestamp in the filename.
    3. Writes the DataFrame to the Excel file with the sheet name 'Results'.
    4. Applies auto-filter to the worksheet.
    5. Adjusts the width of each column based on the maximum length of the values in that column.
    6. Sends the file as an attachment in the response.
    7. Starts a background thread to delete the file after 10 seconds.

    Note:
        This function requires the 'pandas', 'openpyxl', 'flask', 'threading', 'time', and 'os' modules.
    """
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