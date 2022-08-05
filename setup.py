from pathlib import Path

from setuptools import find_packages, setup

import os
import sys

"""ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "src"))"""


VERSION = "2.0.dev0"

with open("requirements.txt", encoding="utf-8") as req:
    requirements = [r.rstrip() for r in req.readlines()]


dev_requirements = []

setup(
    name="opencve",
    version=VERSION,
    author="Nicolas Crocfer",
    author_email="ncrocfer@gmail.com",
    description="CVE Alerting Platform",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/opencve/opencve",
    packages=find_packages(),
    install_requires=requirements,
    extras_require={"dev": dev_requirements},
    include_package_data=True,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Environment :: Web Environment",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
    # entry_points={"console_scripts": ["opencve=opencve.cli:run"]},
    python_requires=">=3.6",
)
