import os
import re
import argparse

def find_dockerfiles(directory):
    # Find all files starting with "Dockerfile" in the specified directory and its subdirectories
    dockerfiles = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.startswith("Dockerfile"):
                dockerfiles.append(os.path.join(root, file))
    return dockerfiles

def extract_apt_dependencies(file_path):
    # Extract dependencies from apt-get or apt install commands
    dependencies = set()
    with open(file_path, 'r') as file:
        content = file.read()
        content = re.sub('#.*$', '', content, flags=re.MULTILINE)
        content = content.replace('\\\n', '')
        # Match apt-get install or apt install commands
        matches = re.findall(r'\bapt(-get)? install\s+([^\n&|;]+)', content)
        for match in matches:
            # Split the matched command to get individual packages, handle cases where install might be followed by options
            packages = re.split(r'\s+', match[1].strip())
            for package in packages:
                if package and not package.startswith('-'):
                    dependencies.add(package)
    return dependencies

def main(directory):
    dockerfiles = find_dockerfiles(directory)
    all_dependencies = {}
    for dockerfile in dockerfiles:
        dependencies = extract_apt_dependencies(dockerfile)
        all_dependencies[dockerfile] = dependencies

    dep_set = set()
    for dockerfile, dependencies in all_dependencies.items():
        for dep in dependencies:
            if '&' in dep or '\\' in dep:
                continue
            dep_set.add(dep)
    dep = list(dep_set)
    dep.sort()
    print('\n'.join(dep))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract apt-get/apt install dependencies from Dockerfile* files.")
    parser.add_argument("directory", type=str, help="Directory to search for Dockerfile* files")
    args = parser.parse_args()
    main(args.directory)

