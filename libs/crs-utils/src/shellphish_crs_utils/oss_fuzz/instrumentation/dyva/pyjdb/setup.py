# -*- coding: iso-8859-1 -*-

import os
from setuptools import setup, find_packages

PACKAGE_NAME = "pyjdb"

# The text of the README file
README = open("README.md").read()

# Get the version number without importing our package
# (which would trigger some ImportError due to missing dependencies)

version_contents = {}
with open(os.path.join(PACKAGE_NAME, "version.py")) as f:
    exec(f.read(), version_contents)

# This call to setup() does all the work
setup(
    name=PACKAGE_NAME,
    version=version_contents["__version__"],
    description=("Python package to interface with the standard CLI "
                 "Java Debugger `jdb` to extract information about the "
                 "execution of Java programs."),
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/jlumbroso/pyjdb",
    author="Jérémie Lumbroso",
    author_email="lumbroso@cs.princeton.edu",
    license="LGPL3",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
    ],
    packages=find_packages(),
    install_requires=[
        "pexpect",
        "typing",
    ],
    include_package_data=True,
)
