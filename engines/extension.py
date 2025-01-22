import logging
import requests
from bs4 import BeautifulSoup
from typing import Optional, Dict

logger = logging.getLogger(__name__)

def get_name_from_id(extension_id: str, proxies: Dict[str, str]) -> Optional[str]:
    """
    Fetch the name of a Chrome extension using its ID.
    
    Args:
        extension_id (str): The ID of the Chrome extension.
        proxy (str): The proxy server to use for the request.
    
    Returns:
        str: The name of the Chrome extension, or None if not found.
    
    Raises:
        Exception: If the request fails or the extension name is not found.
    """
    url = f"https://chromewebstore.google.com/detail/{extension_id}"
    
    try:
        response = requests.get(url, proxies=proxies, verify=False)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'html.parser')
        h1_tag = soup.find('h1')
        if h1_tag:
            return {"name": h1_tag.text.strip(), "url": url}
        else:
            return {"name": "", "url": ""}
    
    except Exception as e:
        logger.error("Error while fetching extension name for ID '%s': %s", extension_id, e, exc_info=True)
        return None