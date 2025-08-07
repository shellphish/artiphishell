#!/usr/bin/env bash
echo "Checking dependencies for $pkg:"
# Use apt-cache depends to get dependencies
apt-cache depends --important "$pkg" | awk '/Depends:/ {print $2}' | while read dep; do
# Check if dependency is installed
if ! dpkg -s "$dep" &>/dev/null; then
    echo "Dependency $dep for package $pkg is not installed."
    # Here you can add commands to handle missing dependencies
    # For example, you might want to add $dep to a list to install
else
    echo "Dependency $dep for package $pkg is already installed."
fi

