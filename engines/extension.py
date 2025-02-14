import logging
import requests
from bs4 import BeautifulSoup
from typing import Optional, Dict

logger = logging.getLogger(__name__)

def get_name_from_id(extension_id: str, proxies: Dict[str, str]) -> Optional[Dict[str, str]]:
    """
    Fetch the name of a Chrome or Edge extension using its ID.
    
    Args:
        extension_id (str): The ID of the extension.
        proxies (Dict[str, str]): The proxy servers to use for the request.
    
    Returns:
        Dict[str, str]: A dictionary containing the name and URL of the extension, or None if not found.
    
    Raises:
        Exception: If the request fails or the extension name is not found.
    """
    chrome_url = f"https://chromewebstore.google.com/detail/{extension_id}"
    edge_url = f"https://microsoftedge.microsoft.com/addons/detail/{extension_id}"
    
    def fetch_extension_name(url: str) -> Optional[Dict[str, str]]:
        try:
            response = requests.get(url, proxies=proxies, verify=False, timeout=5)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            if "microsoftedge.microsoft.com" in url:
                title_tag = soup.find('title')
                if title_tag:
                    return {"name": title_tag.text.strip().split("-")[0].strip(), "url": url}
            else:
                h1_tag = soup.find('h1')
                if h1_tag:
                    return {"name": h1_tag.text.strip(), "url": url}
        
        except Exception as e:
            logger.error("Error while fetching extension name from URL '%s': %s", url, e, exc_info=True)
            return None
    
    result = fetch_extension_name(chrome_url)
    if result and result["name"]:
        return result
    
    result = fetch_extension_name(edge_url)
    if result and result["name"]:
        return result
    
    return None