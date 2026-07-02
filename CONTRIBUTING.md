# Contributing to HyperTraceX

Thank you for your interest in contributing to HyperTraceX!

## Code of Conduct

- Be respectful and professional
- Provide constructive feedback
- Help others learn and grow
- Follow ethical guidelines

## How to Contribute

### Reporting Bugs
1. Check if bug already reported in GitHub Issues
2. Include: OS version, Python version, error message, steps to reproduce
3. Add relevant logs from output directory

### Suggesting Features
1. Describe the feature and use case
2. Explain why it would benefit forensic investigators
3. Provide example usage if possible

### Pull Requests
1. Fork the repository
2. Create feature branch: git checkout -b feature/YourFeature
3. Write clean, documented code
4. Add unit tests for new functionality
5. Run tests: make test
6. Commit: git commit -m "Add YourFeature"
7. Push: git push origin feature/YourFeature
8. Open Pull Request with description

### Code Style
- PEP 8 compliant
- 120 character max line length
- Docstrings for all public methods (Google style)
- Type hints for function signatures
- Descriptive variable names
- Comments for complex logic

### Testing
- Unit tests required for new features
- Integration tests for cross-module functionality
- Run make test before submitting PR
- Test on both Python 3.9 and 3.11

### Commit Messages
- Use present tense: "Add feature" not "Added feature"
- First line max 50 characters
- Reference issues: "Fixes #123"
- Describe what and why, not how

## Development Setup

git clone https://github.com/raffelsfuxk/HyperTraceX.git
cd HyperTraceX
sudo bash install.sh
pip install -r requirements.txt --break-system-packages

## Project Structure
See docs/WIKI.md for architecture overview

## Plugin Development
See plugins/contrib_plugin.py for template and docs/WIKI.md for guide

## Review Process
1. Automated tests must pass
2. Code review by maintainer
3. Documentation updated if needed
4. CHANGELOG updated for significant changes

## Recognition
All contributors will be listed in CONTRIBUTORS.md and release notes.

## Questions?
Open an issue or discussion on GitHub: https://github.com/raffelsfuxk/HyperTraceX

Thank you for contributing to digital forensics!
