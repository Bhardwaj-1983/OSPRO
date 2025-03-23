# OSPRO - Secure File Management System

A secure file management system with user isolation and sandbox capabilities(in development).

NOTE - This is still a simulation and not integrated with any operating system and can be further refined and developed with respect to related factors.

## Features

- User isolation with private directories
- File encryption and decryption
- Sandboxed process execution
- File preview support for various formats
- Security event monitoring
- Process monitoring and control

## Requirements

- Python 3.8 or higher
- Windows operating system
- Required Python packages (see requirements.txt)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/ospro.git
cd ospro
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Install the package in development mode:
```bash
pip install -e .
```

## Building

To build the application:

1. Install build dependencies:
```bash
pip install build twine
```

2. Build the package:
```bash
python -m build
```

This will create:
- `dist/ospro-1.0.0.tar.gz` (source distribution)
- `dist/ospro-1.0.0-py3-none-any.whl` (wheel distribution)

## Running

After installation, you can run the application using:

```bash
ospro
```

Or directly with Python:

```bash
python main.py
```

## Development

1. Install development dependencies:
```bash
pip install -r requirements.txt
```

2. Run tests:
```bash
pytest
```

3. Format code:
```bash
black .
```

4. Check types:
```bash
mypy .
```

5. Lint code:
```bash
flake8
```

## Security Features

- User isolation: Each user has their own private directory
- File encryption: Files can be encrypted using the built-in encryption system
- Sandbox execution: Executable files can be run in an isolated environment
- Process monitoring: Track and control sandboxed processes
- Security events: Monitor and log security-related events
