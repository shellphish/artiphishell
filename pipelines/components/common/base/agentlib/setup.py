from setuptools import setup, find_packages

setup(
    name="agentlib",
    version="0.1.3",
    author="Amy Burnett + Wil Gibbs",
    author_email="wfgibbs@asu.edu",
    description="Library to make writing LLM agent components easy",
    long_description=open("readme.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/your_repo_url",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.10",
    ],
    install_requires=[
        "langchain>=0.1.16",
        "langchain-openai>=0.1.3",
        "langchain_community",
        "langchain-anthropic",
        "Jinja2",
        "chromadb",
        "astunparse",
        "python-dotenv",
        "requests",
        "Flask",
        "GitPython",
        "python-dateutil",
        "redis",
        "pika",
        "pyyaml",
        "pymongo",
        "colorlog",
        "pytest",
        "litellm",
    ],
    include_package_data=True,
    package_data={
        "agentlib": ["prompts/*", "static/*"],
    },
    entry_points={
        "console_scripts": [
            "agentviz = agentlib:web_console_main",
        ],
    },
)
