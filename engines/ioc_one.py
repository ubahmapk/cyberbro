from bs4 import BeautifulSoup
import requests

# Disable SSL warnings in case of proxies like Zscaler which break SSL...
requests.packages.urllib3.disable_warnings()

def query_ioc_one_html(observable, PROXIES):
    """
    Perform a deep search query on ioc.one (HTML).
    
    Args:
        observable (str): The search query.
        PROXIES (dict): Dictionary containing proxy settings.
    
    Returns:
        dict: A dictionary containing the search results.
    """
    try:
        url = f"https://ioc.one/auth/deep_search?search={observable}"
        response = requests.get(url, proxies=PROXIES, verify=False, headers={'User-Agent': 'cyberbro'})
        html_content = response.text

        soup = BeautifulSoup(html_content, 'html.parser')
        cards = soup.find_all('div', class_='card box-shadow my-1')

        search_results = []
        # Limit to 5 results
        for card in cards[:5]:
            header = card.find('div', class_='card-header').text.strip()
            title = card.find('h5', class_='card-title').text.strip()
            source = card.find('a', class_='btn border btn-primary m-1', target='_blank')['href']
            search_results.append({"header": header, "title": title, "source": source})

        return {"results": search_results, "link": url}
    except Exception as e:
        print(e)
    # Always return None in case of failure
    return None
    
def query_ioc_one_pdf(observable, PROXIES):
    """
    Perform a deep search query on ioc.one (PDF).
    
    Args:
        observable (str): The search query.
        PROXIES (dict): Dictionary containing proxy settings.
    
    Returns:
        dict: A dictionary containing the search results.
    """
    try:
        url = f"https://ioc.one/auth/deep_search/pdf?search={observable}"
        response = requests.get(url, proxies=PROXIES, verify=False, headers={'User-Agent': 'cyberbro'})
        html_content = response.text

        soup = BeautifulSoup(html_content, 'html.parser')
        cards = soup.find_all('div', class_='card box-shadow my-1')

        search_results = []
        # Limit to 5 results
        for card in cards[:5]:
            header = card.find('div', class_='card-header').text.strip()
            title = card.find('h5', class_='card-title').text.strip()
            source = card.find('a', class_='btn border btn-primary mx-1', target='_blank')['href']
            search_results.append({"header": header, "title": title, "source": source})

        return {"results": search_results, "link": url}
    except Exception as e:
        print(e)
    # Always return None in case of failure
    return None