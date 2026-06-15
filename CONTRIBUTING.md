# Contributing to CyberShield Toolkit

Thanks for your interest in contributing! Here's how to get started.

## Getting Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-username>/CST.git
   cd CST
   ```
3. **Create a virtual environment** and install dev dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate   # Linux/macOS
   venv\Scripts\activate      # Windows
   pip install -r requirements-dev.txt
   ```

## Development Workflow

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Write your code. Follow existing patterns and conventions.
3. Add or update tests in the `tests/` directory.
4. Run the test suite and make sure everything passes:
   ```bash
   pytest tests/ -v
   ```
5. Format your code:
   ```bash
   black .
   flake8 .
   ```
6. Commit with a clear, descriptive message:
   ```bash
   git commit -m "Add: brief description of your change"
   ```
7. Push your branch and **open a Pull Request** against `main`.

## Code Style

- Follow PEP 8 conventions.
- Use type hints wherever possible.
- Write docstrings for all public functions and classes.
- Keep functions focused — one function, one responsibility.

## Adding a New Module

To add a new scanning/recon module:

1. Create `modules/your_module.py` with a `run(target: str) -> Dict[str, Any]` function.
2. Register it in `main.py` (add CLI option, interactive menu entry, and runner function).
3. Add corresponding tests in `tests/test_your_module.py`.
4. Update the README with usage examples.

## Reporting Issues

Open an issue on GitHub with:
- A clear description of the problem or suggestion.
- Steps to reproduce (if it's a bug).
- Your OS, Python version, and dependency versions.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
