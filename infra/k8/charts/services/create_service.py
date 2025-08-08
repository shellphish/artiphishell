#!/usr/bin/env python3

import argparse
import os
import shutil
import re
import sys
from pathlib import Path

def chdir_to_script_dir():
    """Change the current working directory to the directory containing this script."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    print(f"Changed working directory to: {script_dir}")

chdir_to_script_dir()


def parse_args():
    parser = argparse.ArgumentParser(description='Create a new service from the example template')
    parser.add_argument('service_name', help='Name of the new service')
    parser.add_argument('--port', type=int, default=5000, help='Port number for the service (default: 5000)')
    parser.add_argument('--replace', '-r', action='store_true', help='Replace the service if it already exists')
    return parser.parse_args()

def find_project_root():
    """Find the project root directory by looking for the infra/k8/charts/services directory."""
    current_dir = Path.cwd()
    
    # Try to find the project root by looking for the infra/k8/charts/services directory
    while current_dir != current_dir.parent:
        if (current_dir / 'infra' / 'k8' / 'charts' / 'services').exists():
            return current_dir
        current_dir = current_dir.parent
    
    # If we couldn't find it, use the current directory as a fallback
    print("Warning: Could not find project root. Using current directory as fallback.")
    return Path.cwd()

def copy_example_directory(project_root, service_name, replace=False):
    """Copy the example directory to a new directory with the service name."""
    example_dir = project_root / 'infra' / 'k8' / 'charts' / 'services' / 'example'
    service_dir = project_root / 'infra' / 'k8' / 'charts' / 'services' / service_name
    
    if not example_dir.exists():
        print(f"Error: Example directory not found at {example_dir}")
        sys.exit(1)
    
    if service_dir.exists():
        if replace:
            print(f"Replacing existing service directory at {service_dir}")
            shutil.rmtree(service_dir)
        else:
            print(f"Error: Service directory already exists at {service_dir}")
            print("Use --replace or -r flag to replace the existing service")
            sys.exit(1)
    
    print(f"Copying example directory to {service_dir}")
    shutil.copytree(example_dir, service_dir)
    
    return service_dir

def update_files(service_dir, service_name, port):
    """Recursively update all files in the service directory."""
    print(f"Updating files in {service_dir}")
    
    # Walk through all files in the service directory
    for root, _, files in os.walk(service_dir):
        for file in files:
            file_path = Path(root) / file
            
            # Skip binary files
            if is_binary_file(file_path):
                continue
            
            # Read the file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Replace "example" with the service name (case-sensitive)
            # We need to be careful to match whole words and different case variations
            content = re.sub(r'\bexample\b', service_name, content)
            content = re.sub(r'\bExample\b', service_name.capitalize(), content)
            content = re.sub(r'\bEXAMPLE\b', service_name.upper(), content)
            
            # Replace "example" in template definitions
            content = content.replace('example.', f'{service_name}.')
            
            # Replace port number
            if port != 5000:
                content = re.sub(r'\b5000\b', str(port), content)
            
            # Write the updated content back to the file
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)

def update_artiphishell_chart(project_root, service_name, replace=False):
    """Update the Artiphishell Helm chart to include the new service."""
    chart_file = project_root / 'infra' / 'k8' / 'charts' / 'artiphishell' / 'Chart.yaml'
    
    if not chart_file.exists():
        print(f"Warning: Artiphishell Chart.yaml not found at {chart_file}")
        return False
    
    print(f"Updating Artiphishell Helm chart to include {service_name}")
    
    # Read the Chart.yaml file
    with open(chart_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # More robust check for existing service in dependencies
    # Parse the YAML-like structure to find all service names
    service_names = []
    for line in content.splitlines():
        # Look for lines with "- name: something"
        name_match = re.match(r'\s*-\s*name:\s*(\S+)', line)
        if name_match:
            service_names.append(name_match.group(1))
    
    # Check if our service name is in the list
    if service_name in service_names:
        if not replace:
            print(f"Service '{service_name}' is already included in the Artiphishell Helm chart")
            return True
        else:
            print(f"Replacing existing '{service_name}' dependency in the Artiphishell Helm chart")
            
            # Find and remove the existing dependency block
            lines = content.splitlines()
            new_lines = []
            skip_lines = False
            
            for i, line in enumerate(lines):
                # If we find the service name, start skipping lines
                if re.match(rf'\s*-\s*name:\s*{re.escape(service_name)}$', line):
                    skip_lines = True
                    continue
                
                # If we're skipping and find a new dependency or end of dependencies, stop skipping
                if skip_lines and (re.match(r'\s*-\s*name:', line) or not line.strip()):
                    skip_lines = False
                
                # Add lines we're not skipping
                if not skip_lines:
                    new_lines.append(line)
            
            # Reconstruct the content
            content = '\n'.join(new_lines)
    
    # Find the dependencies section
    dependencies_match = re.search(r'dependencies:', content)
    if not dependencies_match:
        print("Warning: Could not find dependencies section in Artiphishell Chart.yaml")
        return False
    
    # Create the new dependency entry
    new_dependency = f'''  - name: {service_name}
    version: "0.1.0"
    repository: "file://../services/{service_name}"'''
    
    # Try to find the services section
    # First look for existing services dependencies
    services_pattern = r'(  - name: [a-zA-Z0-9-]+\s+version: "0\.1\.0"\s+repository: "file:/\.\./services/[a-zA-Z0-9-]+")'
    services_matches = list(re.finditer(services_pattern, content))
    
    if services_matches:
        # If we found service dependencies, add the new one after the last one
        last_service_match = services_matches[-1]
        last_service_entry = last_service_match.group(0)
        updated_content = content.replace(last_service_entry, f"{last_service_entry}\n{new_dependency}")
    else:
        # If no service dependencies found, try to add it at the end of the dependencies section
        # Find the end of the dependencies section
        dependencies_section_match = re.search(r'dependencies:(.*?)(\n\w+:|$)', content, re.DOTALL)
        if dependencies_section_match:
            dependencies_section = dependencies_section_match.group(1)
            updated_content = content.replace(dependencies_section, f"{dependencies_section}\n{new_dependency}")
        else:
            # As a last resort, just append to the dependencies: line
            updated_content = content.replace("dependencies:", f"dependencies:\n{new_dependency}")
    
    # Write the updated content back to the file
    with open(chart_file, 'w', encoding='utf-8') as f:
        f.write(updated_content)
    
    print(f"Successfully added {service_name} to the Artiphishell Helm chart")
    
    # Update the Chart.lock file by running helm dependency update
    try:
        chart_dir = project_root / 'infra' / 'k8' / 'charts' / 'artiphishell'
        current_dir = os.getcwd()
        
        # Change to the chart directory
        os.chdir(chart_dir)
        
        # Run helm dependency update
        print("Running 'helm dependency update' to update Chart.lock...")
        result = os.system('helm dependency update')
        
        # Change back to the original directory
        os.chdir(current_dir)
        
        if result == 0:
            print("Successfully updated Chart.lock file")
        else:
            print("Warning: Failed to update Chart.lock file. Please run 'helm dependency update' manually in the artiphishell chart directory.")
    except Exception as e:
        print(f"Warning: Error updating Chart.lock file: {e}")
    
    return True

def update_artiphishell_values(project_root, service_name, replace=False):
    """Update the Artiphishell values.yaml file to include configuration for the new service."""
    values_file = project_root / 'infra' / 'k8' / 'charts' / 'artiphishell' / 'values.yaml'
    
    if not values_file.exists():
        print(f"Warning: Artiphishell values.yaml not found at {values_file}")
        return False
    
    print(f"Updating Artiphishell values.yaml to include {service_name} configuration")
    
    # Read the values.yaml file
    with open(values_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # More robust check for existing service in values.yaml
    # Parse the YAML-like structure to find all top-level keys
    service_keys = []
    lines = content.splitlines()
    for i, line in enumerate(lines):
        # Look for lines that define top-level keys (not indented)
        if re.match(r'^[a-zA-Z0-9_-]+:', line):
            key = line.split(':', 1)[0].strip()
            service_keys.append(key)
    
    # Check if our service name is in the list of top-level keys
    if service_name in service_keys:
        if not replace:
            print(f"Service '{service_name}' is already configured in the Artiphishell values.yaml")
            return True
        else:
            print(f"Replacing existing '{service_name}' configuration in the Artiphishell values.yaml")
            
            # Find and remove the existing configuration block
            new_lines = []
            skip_lines = False
            
            for i, line in enumerate(lines):
                # If we find the service name as a top-level key, start skipping lines
                if re.match(rf'^{re.escape(service_name)}:', line):
                    skip_lines = True
                    continue
                
                # If we're skipping and find a new top-level key, stop skipping
                if skip_lines and re.match(r'^[a-zA-Z0-9_-]+:', line):
                    skip_lines = False
                
                # Add lines we're not skipping
                if not skip_lines:
                    new_lines.append(line)
            
            # Reconstruct the content
            content = '\n'.join(new_lines)
    
    # Create the new service configuration
    new_config = f'''
{service_name}:
  enabled: true'''
    
    # Try different strategies to find where to insert the new configuration
    
    # Strategy 1: Find the last service configuration that matches the pattern
    service_pattern = r'([a-zA-Z0-9-]+):\s+enabled: true\s*$'
    service_matches = list(re.finditer(service_pattern, content))
    
    if service_matches:
        # If we found service configurations, add the new one after the last one
        last_service_match = service_matches[-1]
        last_service_config = last_service_match.group(0)
        updated_content = content.replace(last_service_config, f"{last_service_config}{new_config}")
    else:
        # Strategy 2: Try to find any service configuration
        service_pattern = r'([a-zA-Z0-9-]+):\s*\n\s+enabled:'
        service_matches = list(re.finditer(service_pattern, content))
        
        if service_matches:
            # If we found service configurations, add the new one after the last one
            last_service_match = service_matches[-1]
            service_name_match = last_service_match.group(1)
            
            # Find the end of this service's configuration block
            service_block_pattern = rf'{service_name_match}:.*?(\n\w+:|$)'
            service_block_match = re.search(service_block_pattern, content, re.DOTALL)
            
            if service_block_match:
                service_block = service_block_match.group(0)
                updated_content = content.replace(service_block, f"{service_block}{new_config}")
            else:
                # As a last resort, just append to the end of the file
                updated_content = f"{content}\n{new_config}"
        else:
            # As a last resort, just append to the end of the file
            updated_content = f"{content}\n{new_config}"
    
    # Write the updated content back to the file
    with open(values_file, 'w', encoding='utf-8') as f:
        f.write(updated_content)
    
    print(f"Successfully added {service_name} configuration to the Artiphishell values.yaml")
    return True

def is_binary_file(file_path):
    """Check if a file is binary."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            f.read(1024)
        return False
    except UnicodeDecodeError:
        return True

def validate_service_name(service_name):
    """Validate that the service name contains only lowercase alphanumeric characters and hyphens."""
    if not service_name:
        print("Error: Service name cannot be empty")
        sys.exit(1)
    
    if not re.match(r'^[a-z0-9-]+$', service_name):
        print("Error: Service name must contain only lowercase letters, numbers, and hyphens")
        print(f"Invalid service name: '{service_name}'")
        print("Examples of valid service names: 'my-service', 'api', 'auth-service'")
        sys.exit(1)
    
    if service_name.startswith('-') or service_name.endswith('-'):
        print("Error: Service name cannot start or end with a hyphen")
        sys.exit(1)
    
    if '--' in service_name:
        print("Error: Service name cannot contain consecutive hyphens")
        sys.exit(1)
    
    return True

def validate_port(port):
    """Validate that the port number is within a valid range."""
    if not isinstance(port, int):
        print("Error: Port must be an integer")
        sys.exit(1)
    
    if port < 1 or port > 65535:
        print(f"Error: Port number {port} is outside the valid range (1-65535)")
        sys.exit(1)
    
    return True

def main():
    args = parse_args()
    service_name = args.service_name
    port = args.port
    replace = args.replace
    
    # Validate service name
    validate_service_name(service_name)
    
    # Validate port number
    validate_port(port)
    
    # Find the project root
    project_root = find_project_root()
    
    # Copy the example directory
    service_dir = copy_example_directory(project_root, service_name, replace)
    
    # Update files in the new directory
    update_files(service_dir, service_name, port)
    
    # Update the Artiphishell Helm chart
    update_artiphishell_chart(project_root, service_name, replace)
    
    # Update the Artiphishell values.yaml file
    update_artiphishell_values(project_root, service_name, replace)
    
    print(f"Successfully created new service '{service_name}' with port {port}")

if __name__ == '__main__':
    main()
