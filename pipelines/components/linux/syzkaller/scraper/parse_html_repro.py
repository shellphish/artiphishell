import os
import re
import random
import requests
import warnings
from bs4 import BeautifulSoup, SoupStrainer, XMLParsedAsHTMLWarning
warnings.filterwarnings('ignore', category=XMLParsedAsHTMLWarning)

BINSSIZE = 1

def createdir(name):
    d = os.path.join(os.path.dirname(os.path.abspath(__file__)), name)
    os.makedirs(d, exist_ok=True)
    return d

# Create a cache dir
cachedir = createdir("coverage")
logsdir  = createdir("logs")

def parse_cover(filename):
    # Search only html tags like: <pre class="file" id="prog_XYZ">
    strainer = SoupStrainer("pre", attrs={"class": "file","id": re.compile("prog_[0-9]+")})

    with open(filename) as cover:
        soup = BeautifulSoup(cover, 'html.parser', parse_only=strainer)

    return [s.text.strip() for s in soup]

# Download urls only if file is not already present in cachedir
def download_url(url):
    name = url.rsplit('/', 1)[-1]
    filename = os.path.join(cachedir, name)
    if not os.path.isfile(filename):
        with open(filename, 'w') as f:
            f.write(requests.get(url).text)
        print("Done")
    else:
        print("Cached")
    return filename

def list_urls():
    syzbot = requests.get("https://syzkaller.appspot.com/upstream").text
    for link in BeautifulSoup(syzbot, 'html.parser').find_all('a'):
        href = link.get('href')
        if href.startswith("https://storage.googleapis.com/"):
            yield href

def main():
    programs = set()
    for url in list_urls():
        print(f"Downloading {url}.. ", end="")
        filename = download_url(url)

        print(f"Parsing {filename}")
        result = parse_cover(filename)

        print(f"[+] Found {len(result)} programs in {os.path.basename(filename)}\n")
        programs.update(result)

    programs = list(programs)
    random.shuffle(programs)

    # Divide the programs in multiple log files, each containing BINSSIZE files
    for i in range(0, len(programs), BINSSIZE):
        content = ""
        for p in programs[i:i+BINSSIZE]:
            #content += "07:44:19 executing program 0:\n"
            content += p + "\n\n"

        with open(os.path.join(logsdir, f"log{i}"), 'w', encoding="latin-1") as f:
            f.write(content)

    print(f"Total programs found: {len(programs)}")

if __name__ == "__main__":
    main()

