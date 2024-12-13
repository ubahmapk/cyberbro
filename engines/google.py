from googlesearch import search
import requests
# Disable SSL warnings in case of proxies like Zscaler which break SSL...
requests.packages.urllib3.disable_warnings()

def query_google(observable, PROXIES):
    """
    Perform a Google search query limited to 5 search results.
    
    Args:
        observable (str): The search query.
        PROXIES (dict): Dictionary containing proxy settings.
    
    Returns:
        dict: A dictionary containing the search results.
    """
    try:
        # Perform the Google search query
        search_results = search(f"\"{observable}\"", num_results=5, proxy=PROXIES["http"], ssl_verify=False, advanced=True)
        
        # knowing that search results is a generator containing SearchResults objects with title, description, url
        search_results = [{"title": result.title, "description": result.description, "url": result.url} for result in search_results]
        # Return the search results
        
        return {"results": search_results}
    except Exception as e:
        print(e)
    # Always return None in case of failure
    return None