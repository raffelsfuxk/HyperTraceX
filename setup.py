#!/usr/bin/env python3
"""HyperTraceX Setup Script - Package installation."""

from setuptools import setup, find_packages
import os

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="tracex",
    version="1.0.0",
    author="raffelsfuxk",
    author_email="tracex@example.com",
    description="Enterprise Digital Forensics Platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/raffelsfuxk/HyperTraceX",
    packages=find_packages(
        include=["core", "core.*", "modules", "modules.*", 
                 "ai", "ai.*", "enterprise", "enterprise.*",
                 "reporting", "reporting.*", "dashboard", "dashboard.*",
                 "cli", "cli.*", "plugins", "plugins.*"]
    ),
    py_modules=["tracex"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Legal Industry",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: POSIX :: Linux",
        "Environment :: Console",
        "Environment :: Web Environment",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "tracex=tracex:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
