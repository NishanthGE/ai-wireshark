# Contributing to AI Wireshark

Thanks for your interest in contributing! Here's how to get started.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/ai-wireshark.git`
3. Create a virtual environment: `python3 -m venv venv`
4. Install dependencies: `venv/bin/pip install -r requirements.txt`
5. Copy `.env.example` to `.env` and add your API keys
6. Create a branch: `git checkout -b feature/your-feature`

## Development

- Run the tool: `sudo venv/bin/python3 main.py`
- Web dashboard: `http://localhost:8080`
- Test without AI: `sudo venv/bin/python3 main.py --no-ai`
- Test with pcap: `venv/bin/python3 main.py --pcap capture.pcap`

## Submitting Changes

1. Commit your changes with a clear message
2. Push to your fork
3. Open a Pull Request with a description of what you changed and why

## Guidelines

- Keep PRs focused on a single change
- Test your changes on a live interface before submitting
- Don't commit API keys or `.env` files
- Follow existing code style (Python, no type stubs needed)

## Reporting Bugs

Open an issue with:
- What you expected to happen
- What actually happened
- Steps to reproduce
- Your OS and Python version

## Feature Ideas

Open an issue tagged `enhancement` describing the feature and its use case.
