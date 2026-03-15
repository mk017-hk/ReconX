from setuptools import setup, find_packages

setup(
    name="reconx",
    version="1.0.0",
    description="All-in-one reconnaissance & pentesting toolkit",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "aiohttp>=3.9.0",
        "dnspython>=2.4.0",
        "rich>=13.7.0",
        "click>=8.1.0",
        "python-whois>=0.8.0",
        "cryptography>=41.0.0",
        "requests>=2.31.0",
    ],
    entry_points={
        "console_scripts": [
            "reconx=reconx.cli:cli",
        ],
    },
    include_package_data=True,
    package_data={
        "reconx": ["wordlists/*.txt"],
    },
)
