# Makefile to simplify some common development tasks.
# Run 'make help' for a list of commands.

#PYTHON=`which python`
PY=python -m py_compile
PYTHON='C:/Users/gleveill/PycharmProjects/venv/bastionenv/Scripts/python.exe'
TW=twine

default: help

help:
	@echo "Available commands:"
	@sed -n '/^[a-zA-Z0-9_.]*:/s/:.*//p' <Makefile | sort

test:
	tox

coverage:
	pytest --cov=sqlparse --cov-report=html --cov-report=term

clean:
	$(PYTHON) setup.py clean
	@find . -name '*.pyc' -delete
	@find . -name '*~' -delete

release:
	#@rmdir /S /Q dist
	$(PYTHON) -m build --no-isolation
	@twine upload --repository artifactory dist/* --config-file .\repo.conf