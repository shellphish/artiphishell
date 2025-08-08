import setuptools

setuptools.setup(
    name="morpheus",
    version="0.1.0",
    author="Nicola Ruaro",
    author_email="ruaronicola@ucsb.edu",
    description="Automatic grammar composition library for fuzzing of deeply nested file formats",
    packages=setuptools.find_packages(),
    python_requires=">=3.7",
    install_requires=[
        "filetype",
        "ipython",
        "python-magic",
        "networkx",
        "pytest",
        "pandas==2.1.4"
    ],
)