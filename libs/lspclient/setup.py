# setup.py
from setuptools import setup, find_packages

setup(
    name="lspclient",  # Package name
    version="0.1.0",  # Initial version
    packages=find_packages(),
    include_package_data=True,
    package_data={"lspclient": ["clangd.json"]},
    description="A simple LSP client for interacting with language servers",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="ammonia",
    author_email="ammonial@shellphish-support-syndicate.io",
    url="https://github.com/shellphish-support-syndicate/lspclient",  # Repository URL
    license="MIT",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=[
        # List any dependencies here, for example:
        # "some_dependency>=1.0",
    ],
)
