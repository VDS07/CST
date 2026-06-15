"""Setup configuration for CyberShield Toolkit."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="cybershield-toolkit",
    version="1.0.0",
    author="VDS07",
    author_email="",
    description="A modular Python toolkit for network reconnaissance and security auditing.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/VDS07/CST",
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "cybershield=main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Intended Audience :: Information Technology",
        "Development Status :: 4 - Beta",
    ],
    keywords="cybersecurity network scanner dns whois security-headers",
)
