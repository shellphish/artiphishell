#!/usr/bin/env python3
"""
Pipeline Backup Checker Script

This script connects to the pipeline backup webpage, checks for target names,
retrieves run IDs with timestamps, and finds the newest run containing all
required components.

Usage:
    python pipeline_checker.py <target_name>
"""

import sys
import argparse
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import re
from urllib.parse import urljoin

# Hardcoded list of required components to check for
REQUIRED_COMPONENTS = [
    'codeql_build.codeql_database_path',
]

class PipelineChecker:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        # Set a user agent to avoid being blocked
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def get_page_content(self, url):
        """Fetch and parse webpage content"""
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            return BeautifulSoup(response.content, 'html.parser')
        except requests.RequestException as e:
            raise Exception(f"Failed to fetch {url}: {e}")

    def extract_directory_listing(self, soup):
        """Extract directory names and timestamps from Apache directory listing"""
        directories = []
        files = []
        
        # Look for links in the directory listing
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            
            # Skip parent directory
            if href in ['../', '../']:
                continue
            
            # Try to find timestamp in the same row
            timestamp = None
            parent_row = link.find_parent('tr') or link.find_parent()
            timestamp_match = None
            
            if parent_row:
                # Look for timestamp pattern in the row text
                row_text = parent_row.get_text()
                timestamp_match = re.search(r'(\d{2}-\w{3}-\d{4}\s+\d{2}:\d{2})', row_text)
                if timestamp_match:
                    timestamp_str = timestamp_match.group(1)
                    try:
                        timestamp = datetime.strptime(timestamp_str, '%d-%b-%Y %H:%M')
                    except ValueError:
                        # If parsing fails, keep timestamp as string
                        timestamp = timestamp_str
            
            item_data = {
                'name': href.rstrip('/') if href.endswith('/') else href,
                'timestamp': timestamp,
                'timestamp_str': timestamp_match.group(1) if timestamp_match else 'Unknown',
                'is_directory': href.endswith('/')
            }
            
            if href.endswith('/'):
                directories.append(item_data)
            else:
                files.append(item_data)
        
        return directories + files

    def check_components_in_run(self, target_name, run_id):
        """Check if all required components exist in a specific run"""
        run_url = urljoin(self.base_url, f"{target_name}/{run_id}/")
        print(f"  🔗 Checking run URL: {run_url}")
        
        try:
            soup = self.get_page_content(run_url)
            items = self.extract_directory_listing(soup)
            
            available_components = [item['name'] for item in items if item['is_directory']]
            
            missing_components = []
            for component in REQUIRED_COMPONENTS:
                # Check for exact match or partial match (for components ending with ..)
                if component.endswith('..'):
                    component_prefix = component[:-2]
                    matching_component = None
                    for comp in available_components:
                        if comp.startswith(component_prefix):
                            matching_component = comp
                            break
                    
                    if not matching_component:
                        print(f"  📂❌ Folder '{component_prefix}*' not found")
                        print(f"      Available folders: {', '.join(available_components[:5])}")
                        missing_components.append(component)
                    else:
                        print(f"  📂✅ Folder '{matching_component}' found")
                        # Check if the component directory contains files
                        component_url = urljoin(run_url, f"{matching_component}/")
                        print(f"    🔗 Checking component URL: {component_url}")
                        try:
                            component_soup = self.get_page_content(component_url)
                            component_items = self.extract_directory_listing(component_soup)
                            
                            # Look for files (items that are not directories)
                            files = [item['name'] for item in component_items if not item['is_directory']]
                            
                            if files:
                                print(f"    📄✅ Files found: {', '.join(files[:3])}" + 
                                     (f" (and {len(files)-3} more)" if len(files) > 3 else ""))
                            else:
                                print(f"    📄❌ No files found in folder")
                                missing_components.append(component)
                        except Exception as e:
                            print(f"    ⚠️ Could not check folder contents: {e}")
                            missing_components.append(component)
                else:
                    if component not in available_components:
                        print(f"  📂❌ Folder '{component}' not found")
                        print(f"      Available folders: {', '.join(available_components[:5])}")
                        missing_components.append(component)
                    else:
                        print(f"  📂✅ Folder '{component}' found")
                        # Check if the component directory contains files
                        component_url = urljoin(run_url, f"{component}/")
                        print(f"    🔗 Checking component URL: {component_url}")
                        try:
                            component_soup = self.get_page_content(component_url)
                            component_items = self.extract_directory_listing(component_soup)
                            
                            # Look for files (items that are not directories)
                            files = [item['name'] for item in component_items if not item['is_directory']]
                            
                            if files:
                                print(f"    📄✅ Files found: {', '.join(files[:3])}" + 
                                     (f" (and {len(files)-3} more)" if len(files) > 3 else ""))
                            else:
                                print(f"    📄❌ No files found in folder")
                                missing_components.append(component)
                        except Exception as e:
                            print(f"    ⚠️ Could not check folder contents: {e}")
                            missing_components.append(component)
            
            return len(missing_components) == 0, missing_components
            
        except Exception as e:
            print(f"Warning: Could not check components for run {run_id}: {e}")
            return False, REQUIRED_COMPONENTS

    def get_run_ids(self, target_name):
        """Get all run IDs for a given target with their timestamps"""
        target_url = urljoin(self.base_url, f"{target_name}/")
        print(f"Fetching run IDs from: {target_url}")
        print(f"🔗 Target URL: {target_url}")
        
        soup = self.get_page_content(target_url)
        items = self.extract_directory_listing(soup)
        
        run_ids = []
        for item in items:
            # Run IDs are typically numeric directories
            if item['is_directory'] and item['name'].isdigit():
                run_ids.append(item)
        
        if not run_ids:
            raise Exception(f"No run IDs found for target '{target_name}'")
        
        print(f"Found {len(run_ids)} run IDs")
        return run_ids

    def check_target_exists(self, target_name):
        """Check if target exists in the main directory listing"""
        print(f"Checking if target '{target_name}' exists...")
        print(f"🔗 Checking base URL: {self.base_url}")
        
        soup = self.get_page_content(self.base_url)
        items = self.extract_directory_listing(soup)
        
        target_names = [item['name'] for item in items if item['is_directory']]
        
        if target_name not in target_names:
            available_targets = ', '.join(target_names[:10])  # Show first 10
            if len(target_names) > 10:
                available_targets += f", ... and {len(target_names) - 10} more"
            raise Exception(f"Target '{target_name}' not found. Available targets: {available_targets}")
        
        print(f"Target '{target_name}' found!")
        return True

    def find_newest_complete_run(self, target_name):
        """Find the newest run ID that contains all required components"""
        run_ids = self.get_run_ids(target_name)
        
        # Convert run IDs to integers and sort in descending order (largest first)
        run_ids_numeric = []
        for run_data in run_ids:
            try:
                run_id_int = int(run_data['name'])
                run_ids_numeric.append({
                    'name': run_data['name'],
                    'timestamp_str': run_data['timestamp_str'],
                    'numeric_id': run_id_int
                })
            except ValueError:
                # Skip non-numeric run IDs
                continue
        
        # Sort by numeric run ID in descending order (largest first)
        sorted_run_ids = sorted(run_ids_numeric, key=lambda x: x['numeric_id'], reverse=True)
        
        if not sorted_run_ids:
            raise Exception("No valid numeric run IDs found")
        
        print(f"Checking runs for required components (largest run ID first)...")
        
        for run_data in sorted_run_ids:
            run_id = run_data['name']
            timestamp = run_data['timestamp_str']
            
            print(f"Checking run {run_id} ({timestamp})...")
            
            has_all_components, missing_components = self.check_components_in_run(target_name, run_id)
            
            if has_all_components:
                print(f"✓ Run {run_id} contains all required components!")
                return run_id, timestamp
            else:
                print(f"✗ Run {run_id} missing {len(missing_components)} components")
                if len(missing_components) <= 5:  # Show first few missing components
                    print(f"  Missing: {', '.join(missing_components[:5])}")
        
        raise Exception("No run found that contains all required components")

def main():
    parser = argparse.ArgumentParser(description='Check pipeline backup for target and find newest complete run')
    parser.add_argument('target_name', help='Name of the target to check')
    parser.add_argument('--url', default='https://aixcc-diskman.adamdoupe.com/iKbr6hfymftxL7pr3FEX/pipeline-backup/',
                       help='Base URL of the pipeline backup (default: %(default)s)')
    
    args = parser.parse_args()
    
    try:
        checker = PipelineChecker(args.url)
        
        # Check if target exists
        checker.check_target_exists(args.target_name)
        
        # Find newest complete run
        run_id, timestamp = checker.find_newest_complete_run(args.target_name)
        
        print(f"\n🎉 SUCCESS!")
        print(f"Target: {args.target_name}")
        print(f"Newest complete run ID: {run_id}")
        print(f"Run timestamp: {timestamp}")
        
        return 0
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())