import os
import requests
from collections import defaultdict
from pathlib import Path
import time
import json
def parse_url(url):
    # Split by forward slashes and get the second last part
    # Example: from ".../libFuzzer/simdjson_fuzz_element/public.zip"
    # We want "simdjson_fuzz_element"
    split_url = url.split('/')
    if len(split_url) >= 2:
        return split_url[-2]
    return ""


def extract_project_and_harness(full_name, project_names):
    """
    Extract project and harness name from a string like 'simdjson_fuzz_element'
    where project name is from project_names list and harness is the remainder
    """
    for project_name in project_names:
        if project_name in full_name:
            #import ipdb; ipdb.set_trace()
            # Remove the project name and any underscores
            harness_name = full_name.replace(project_name, "").strip("_")
            #harness_name = full_name.split(proejct_name)[0].strip("_")
            return project_name, harness_name

    return None, None

def download_zip(url, save_path):
    try:
        time.sleep(2)
        response = requests.get(url)
        response.raise_for_status()

        # Create parent directories if they don't exist
        os.makedirs(os.path.dirname(save_path), exist_ok=True)

        # Save the downloaded content
        with open(save_path, 'wb') as f:
            f.write(response.content)
        #print(f"Successfully downloaded {url} to {save_path}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error downloading {url}: {e}")
        return False

def main():
    with open('oss-fuzz-projects-c', 'r') as r:
        project_names = [line.strip() for line in r.readlines() if line.strip()]

    url_file = 'oss_fuzz_corpus_urls.txt'
    with open(url_file, 'r') as f:
        urls_to_check = [line.strip() for line in f.readlines() if line.strip()]

    # Dictionary to store project -> harness mappings
    project_harness = defaultdict(list)

    for url in urls_to_check:
        full_name = parse_url(url)

        if not full_name:
            print(f"Couldn't parse URL correctly: {url}")
            continue
        #import ipdb; ipdb.set_trace()
        # Extract project and harness names
        project_name, harness_name = extract_project_and_harness(full_name, project_names)

        if project_name and harness_name:
            # Add to our mapping if not already present
            if harness_name not in project_harness[project_name]:
                project_harness[project_name].append(harness_name)

            # Create directory structure: project-name/harness-name/
            save_dir = os.path.join("oss-fuzz-corpus-c", project_name, harness_name)
            zip_path = os.path.join(save_dir, "public.zip")

            print(f"Project: {project_name}, Harness: {harness_name}")
            #print(f"Downloading {url} to {zip_path}")
            download_zip(url, zip_path)

    # Print summary of what we found
    print("\nSummary:")
    with open("oss-fuzz-project-harness-pairs.json", "w") as w:
        w.write(json.dumps(dict(project_harness)))
    #for project, harnesses in project_harness.items():
        #print(f"Project: {project}, Harnesses: {', '.join(harnesses)}")
    print(f"Total projects: {len(project_harness)}")
    total_harnesses = sum(len(harnesses) for harnesses in project_harness.values())
    print(f"Total harnesses: {total_harnesses}")

if __name__ == "__main__":
    main()
