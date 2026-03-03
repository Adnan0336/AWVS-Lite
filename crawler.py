import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urldefrag

def crawl(session: requests.Session, url: str, timeout: int = 8, limit: int = 30):
    """
    Lightweight crawler used ONLY to discover same-page links for reporting context.
    Not used for exploitation or high-volume crawling.
    """
    discovered = []
    try:
        r = session.get(url, timeout=timeout, allow_redirects=True)
        soup = BeautifulSoup(r.text or "", "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href:
                continue
            abs_url = urljoin(url, href)
            abs_url, _ = urldefrag(abs_url)
            if abs_url not in discovered:
                discovered.append(abs_url)
            if len(discovered) >= limit:
                break
    except Exception:
        return []
    return discovered
