import requests
from bs4 import BeautifulSoup


def collect_http_evidence(target):

    try:

        response = requests.get(
            target,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": "MagnoCyber/0.1"
            }
        )

        detected_encoding = response.apparent_encoding or response.encoding or "utf-8"

        html = response.content.decode(
            detected_encoding,
            errors="replace"
        )

        soup = BeautifulSoup(html, "html.parser")

        title = ""

        if soup.title:
            title = fix_mojibake(soup.title.get_text(strip=True))

        links = []

        for link in soup.find_all("a", href=True):

            href = link["href"]

            if href not in links:
                links.append(href)

        return {
            "collector": "web",
            "target": target,
            "status_code": response.status_code,
            "final_url": response.url,
            "encoding": response.encoding,
            "apparent_encoding": response.apparent_encoding,
            "used_encoding": detected_encoding,
            "title": title,
            "headers": dict(response.headers),
            "links": links[:100],
            "html_sample": fix_mojibake(html[:5000])
        }

    except Exception as e:

        return {
            "collector": "web",
            "target": target,
            "error": str(e)
        }

def fix_mojibake(text):
    try:
        return text.encode("latin1").decode("utf-8")
    except Exception:
        return text        
