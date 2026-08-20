"""
Setup script for S7Pwn
For backwards compatibility with older pip versions
Modern installations should use pyproject.toml
"""
from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
readme_file = Path(__file__).parent / "README.md"
long_description = ""
if readme_file.exists():
    with open(readme_file, encoding="utf-8") as f:
        long_description = f.read()

# Read version from version.py
version = "1.0.0"
try:
    exec(open("s7pwn/version.py").read())
    version = __version__
except:
    pass

setup(
    name="s7pwn",
    version=version,
    description="S7Pwn – Siemens PLC Security Testing Tool with Web GUI",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="S7Pwn Team",
    author_email="",
    url="https://github.com/your-repo/S7.Pwn",
    license="MIT",

    packages=find_packages(exclude=["tests", "tests.*"]),

    # Package data
    package_data={
        "s7pwn": [
            "device_map/*.json",
            "templates/*.html",
            "static/*",
        ]
    },

    include_package_data=True,

    # Dependencies
    install_requires=[
        "python-snap7",
        "scapy",
        "prompt_toolkit>=3.0.36",
        "flask>=2.3.0",
    ],

    # Windows-specific dependencies
    extras_require={
        "windows": [
            "wmi",
            "pywin32",
        ],
        "dev": [
            "pytest",
            "black",
            "flake8",
            "pyinstaller",
        ],
    },

    # Entry points
    entry_points={
        "console_scripts": [
            "s7pwn=s7pwn.cli:main",
            "s7pwn-webgui=s7pwn.web_gui:start_web_gui",
        ],
    },

    # Classifiers
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
    ],

    keywords="security pentesting plc siemens s7 scada ics",

    python_requires=">=3.9",

    zip_safe=False,
)
