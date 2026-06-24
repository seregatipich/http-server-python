.PHONY: clean

clean:
	rm -rf .mypy_cache .pytest_cache .ruff_cache src/*.egg-info
	rm -f .DS_Store *.log
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name '*.py[cod]' -delete
