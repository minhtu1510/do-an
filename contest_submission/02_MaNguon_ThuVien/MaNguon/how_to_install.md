# How to Install S7Pwn

S7Pwn is a Siemens PLC pentest CLI tool. Follow these steps to install it on your system.

## Prerequisites

- Python 3.9 or higher
- Git (optional, for cloning the repository)
- Administrative privileges (for some operations)

## Installation Steps

1. **Clone or Download the Repository**

   If using Git:
   ```
   git clone <repository-url>
   cd PLCPentest_Release
   ```

   Or download and extract the ZIP file to your desired location.

2. **Set Up a Virtual Environment (Recommended)**

   Create and activate a virtual environment to isolate dependencies:
   ```
   python -m venv venv
   venv\Scripts\activate
   ```

3. **Install Build Tools**

   Install the `build` package to build the project:
   ```
   pip install build
   ```

4. **Build the Package**

   Build the package in development mode:
   ```
   python -m build
   ```

5. **Install the Package**

   Install the package in editable mode for development:
   ```
   pip install -e .
   ```

6. **Verify Installation**

   Check if S7Pwn is installed correctly:
   ```
   s7pwn --help
   ```

   Or run the CLI:
   ```
   s7pwn
   ```

## Dependencies

The tool requires the following Python packages:
- python-snap7
- scapy
- wmi (Windows only)
- pywin32 (Windows only)
- prompt_toolkit (>=3.0.36)

These are automatically installed during the build process.

## Troubleshooting

- If you encounter permission errors, run the command prompt as Administrator.
- Ensure Python 3.9+ is installed and added to your PATH.
- If virtual environment activation fails, check the path to `venv\Scripts\activate`.

## Usage

After installation, start the tool with:
```
s7pwn
```

Use `help` command within the CLI for available commands.





