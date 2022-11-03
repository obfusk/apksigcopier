SHELL   := /bin/bash
PYTHON  ?= python3

export PYTHONWARNINGS := default

.PHONY: all install test test-cli lint lint-extra clean cleanup
.PHONY: test-apks test-apks-compare test-apks-copy

all: apksigcopier.1

install:
	$(PYTHON) -mpip install -e .

test: test-cli lint lint-extra

test-cli:
	# TODO
	apksigcopier --version
	$(PYTHON) -m doctest apksigcopier/__init__.py

test-apks: test-apks-compare test-apks-copy

test-apks-compare:
	cd test/apks && diff -Naur ../test-compare.out <( ../test-compare.sh \
	  | sed -r 's!/tmp/[^/]*/!/tmp/.../!' \
	  | sed -r 's!Expected: <[0-9a-f]+>, actual: <[0-9a-f]+>!Expected: <...>, actual: <...>!' )

test-apks-copy:
	cd test/apks && diff -Naur ../test-copy.out <( $(PYTHON) ../test-copy.py )

lint:
	flake8 apksigcopier/__init__.py
	pylint apksigcopier/__init__.py

lint-extra:
	mypy apksigcopier/__init__.py

clean: cleanup
	rm -fr apksigcopier.egg-info/

cleanup:
	find -name '*~' -delete -print
	rm -fr __pycache__/ .mypy_cache/
	rm -fr build/ dist/
	rm -fr .coverage htmlcov/
	rm -fr apksigcopier.1

%.1: %.1.md
	pandoc -s -t man -o $@ $<

.PHONY: _package _publish

_package:
	SOURCE_DATE_EPOCH="$$( git log -1 --pretty=%ct )" \
	  $(PYTHON) setup.py sdist bdist_wheel
	twine check dist/*

_publish: cleanup _package
	read -r -p "Are you sure? "; \
	[[ "$$REPLY" == [Yy]* ]] && twine upload dist/*
