#!/usr/bin/env python

"""The setup script."""

from setuptools import find_packages, setup

with open("README.rst") as readme_file:
    readme = readme_file.read()

requirements = [
    "aiohttp>=3.7.4,<4",
    "asn1>=2.4.1",
    "python-dateutil>=2.8.1",
    "tenacity>=8.0.1",
]

setup_requirements = ["pytest-runner"]

test_requirements = ["pytest>=3"]

setup(
    author="Graham Wetzler",
    author_email="graham@wetzler.dev",
    python_requires=">=3.6",
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ],
    description="Package to connect to and retrieve data from the unofficial \
Smart Meter Texas API",
    install_requires=requirements,
    license="MIT license",
    long_description=readme,
    include_package_data=True,
    keywords="smart_meter_texas",
    name="smart_meter_texas",
    packages=find_packages(include=["smart_meter_texas", "smart_meter_texas.*"]),
    setup_requires=setup_requirements,
    test_suite="tests",
    tests_require=test_requirements,
    url="https://github.com/grahamwetzler/smart-meter-texas",
    version="0.5.2",
    zip_safe=False,
)
