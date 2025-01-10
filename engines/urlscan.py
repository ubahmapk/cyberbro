import json
import requests

# Disable SSL warning
requests.packages.urllib3.disable_warnings()

def query_urlscan(observable, observable_type, PROXIES):
    """
    Queries the urlscan.io API for information about a given observable.

    Args:
        observable (str): The observable to query (e.g., a URL, IP, or hash).
        observable_type (str): The type of the observable (e.g., "URL", "IP", "HASH").
        PROXIES (dict): A dictionary of proxies to use for the request.

    Returns:
        dict: A dictionary containing the scan count, top domains, and a link to the urlscan.io search results.
              Example:
              {
                  "scan_count": 10,
                  "top_domains": [
                      {"domain": "example.com", "count": 5},
                      {"domain": "example.org", "count": 3},
                      {"domain": "example.net", "count": 2}
                  ],
                  "link": "https://urlscan.io/search/#page.domain:observable"
              }
        None: If an error occurs during the request or processing.

    Raises:
        Exception: If an error occurs during the request or processing.
    """

    query_fields = {
        "IPv4": "ip",
        "IPv6": "ip",
        "MD5": "files.md5",
        "SHA1": "files.sha1",
        "SHA256": "files.sha256",
        "URL": "page.domain",
        "FQDN": "page.domain"
    }

    query_field = query_fields.get(observable_type, "page.domain")

    if observable_type == "URL":
        observable = observable.split("/")[2].split(":")[0]

    url = f"https://urlscan.io/api/v1/search/?q={query_field}:{observable}"

    try:
        response = requests.get(url, proxies=PROXIES, verify=False)
        response.raise_for_status()
        result = response.json()

        results = result.get("results", [])

        scan_count = result.get("total", 0)

        domain_count = {}
        
        for entry in results:
            page = entry.get("page", {})
            domain = page.get("domain", "Unknown")
            domain_count[domain] = domain_count.get(domain, 0) + 1

        sorted_domains = sorted(domain_count.items(), key=lambda domain_count_item: domain_count_item[1], reverse=True)
        top_domains = sorted_domains[:5]
        
        top_domains_list = [{"domain": domain, "count": count} for domain, count in top_domains]

        return {
            "scan_count": scan_count,
            "top_domains": top_domains_list, 
            "link": f"https://urlscan.io/search/#{query_field}:{observable}"
        }

    except Exception as e:
        print(e)
    # Always return None in case of failure
    return None