# Contributing to Splunk Detection Engineer Agent

Thank you for your interest in contributing to the Splunk Detection Engineer Agent! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please be respectful and constructive in all interactions. We're building tools to help security professionals, and collaboration is key.

## Getting Started

### Prerequisites

- Python 3.11 or higher
- Git
- Access to a Splunk Enterprise instance (for full testing)
- API key for at least one LLM provider (Groq recommended for free tier)

### Development Setup

```bash
# 1. Fork and clone the repository
git clone https://github.com/yourusername/splunk-detection-engineer-agent.git
cd splunk-detection-engineer-agent

# 2. Create a virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install development dependencies
pip install pytest pytest-cov black ruff mypy

# 5. Install Playwright browser
playwright install chromium

# 6. Set up configuration
cp config/config.yaml.example config/config.yaml
# Edit config/config.yaml with your API keys
```

### Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest --cov=src tests/

# Run specific test file
pytest tests/test_agent.py
```

### Code Style

We use the following tools for code quality:

```bash
# Format code with Black
black src/ tests/

# Lint with Ruff
ruff check src/ tests/

# Type checking with mypy
mypy src/
```

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/yourusername/splunk-detection-engineer-agent/issues)
2. If not, create a new issue with:
   - Clear, descriptive title
   - Steps to reproduce
   - Expected vs actual behavior
   - Python version, OS, and relevant configuration
   - Error messages and stack traces

### Suggesting Features

1. Open an issue with the `enhancement` label
2. Describe the use case and why it would be valuable
3. Provide examples of how it would work

### Pull Request Process

1. **Fork the repository** and create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**:
   - Follow existing code style and patterns
   - Add tests for new functionality
   - Update documentation as needed

3. **Test your changes**:
   ```bash
   pytest tests/
   black --check src/
   ruff check src/
   ```

4. **Commit with clear messages**:
   ```bash
   git commit -m "feat: add support for new LLM provider"
   # or
   git commit -m "fix: handle empty response from Splunk API"
   ```

5. **Push and create PR**:
   ```bash
   git push origin feature/your-feature-name
   ```
   Then open a Pull Request on GitHub.

6. **PR Review**:
   - Address any feedback from maintainers
   - Keep the PR focused on a single change
   - Ensure CI checks pass

### Commit Message Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `style:` - Code style changes (formatting)
- `refactor:` - Code refactoring
- `test:` - Adding or updating tests
- `chore:` - Maintenance tasks

## Project Structure

```
splunk-detection-engineer-agent/
├── src/                    # Source code
│   ├── agent/              # Main agent package (modularized)
│   │   ├── orchestrator.py # Main SplunkAgent class
│   │   ├── handlers.py     # Input type handlers
│   │   ├── validation.py   # Query validation
│   │   └── cli.py          # CLI interface
│   ├── api/                # FastAPI web backend
│   ├── rag_*.py            # RAG modules (spl_docs, detections, cim, attack_data)
│   ├── fetcher_*.py        # Data fetchers (smart update)
│   └── llm_provider.py     # LLM abstraction
├── web/                    # Web interface (vanilla HTML/JS/CSS)
├── prompts/                # External prompt files
├── data/                   # Data files (JSONL + stats)
├── docs/                   # Documentation
├── examples/               # Usage examples
├── tests/                  # Test files
└── config/                 # Configuration templates
```

## Areas for Contribution

- **New LLM providers**: Add support for additional LLM APIs
- **Detection rules**: Expand the detection rules knowledge base
- **Documentation**: Improve docs, add examples, fix typos
- **Testing**: Add unit tests, integration tests
- **Performance**: Optimize query generation and RAG retrieval
- **Bug fixes**: Address issues in the tracker

## Questions?

- Open a [Discussion](https://github.com/yourusername/splunk-detection-engineer-agent/discussions)
- Check existing issues for similar questions
- Review the documentation in `docs/`

Thank you for contributing!
