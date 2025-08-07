#!/bin/bash

VERSION=$(cat /etc/os-release | grep 'VERSION_ID=' | sed 's/VERSION_ID=//g' | tr -d '"')

dpkg -i -R /shellphish/dependencies/$VERSION/ || \
dpkg -i -R /shellphish/dependencies/22.04/ || \
dpkg -i -R /shellphish/dependencies/20.04/ || \
sudo dpkg -i -R /shellphish/dependencies/$VERSION/ || \
sudo dpkg -i -R /shellphish/dependencies/22.04/ || \
sudo dpkg -i -R /shellphish/dependencies/20.04/

# dpkg -i /shellphish/dependencies/$VERSION/*.deb || \
# dpkg -i /shellphish/dependencies/22.04/*.deb || \
# dpkg -i /shellphish/dependencies/20.04/*.deb || \
# sudo dpkg -i /shellphish/dependencies/$VERSION/*.deb || \
# sudo dpkg -i /shellphish/dependencies/22.04/*.deb || \
# sudo dpkg -i /shellphish/dependencies/20.04/*.deb