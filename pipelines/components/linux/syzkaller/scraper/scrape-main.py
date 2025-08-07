import requests
from bs4 import BeautifulSoup
import json

bugs_json = {}

base_url = "https://syzkaller.appspot.com"
url = "https://syzkaller.appspot.com/upstream/fixed" 

# Send a GET request to the webpage
response = requests.get(url)

# Parse the HTML content of the webpage
soup = BeautifulSoup(response.content, "html.parser")

# Find the table element
table = soup.find("table",class_="list_table")

# We get all the rows of the bugs table
bug_rows = table.find_all("tr")
bug_rows.pop(0) # Remove the first row (header of the table)

for idx,bug_title in enumerate(bug_rows):
    if bug_title.find("td",class_='stat').text == "":
        print(f"[{idx}]The bug has no reproducers")
        continue
    bug = bug_title.find("td",class_='title').find("a")
    bug_title = bug.text
    bug_url = bug.get("href")
    bugs_json[bug_title] = base_url + bug_url
    #print(f"[!] bug_title: {bug_title} and url {bug_url}")

open("bugs.json","w").write(json.dumps(bugs_json,indent=4))
