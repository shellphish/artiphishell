from setuptools import setup, find_packages

setup(
    name="testguy",
    version="0.1.0",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=['junitparser'],
    author="Saad Ullah",
    author_email="saadu@bu.edu",
    description="A testing utility",
    url="https://github.com/shellphish-support-syndicate/artiphishell/libs/testguy",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
