from setuptools import setup, find_packages

setup(
    name="coveragelib",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "pyyaml",
        "lxml",
        "beautifulsoup4",
    ],
    python_requires=">=3.8",
)
