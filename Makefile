SHELL     := /bin/bash
PYTHON    ?= python3

PYCOV     := $(PYTHON) -mcoverage run --source apksigcopier
PYCOVCLI  := $(PYCOV) -a apksigcopier/__init__.py

export PYTHONWARNINGS := default

.PHONY: all install test test-cli doctest coverage lint lint-extra clean cleanup
.PHONY: test-apks test-apks-compare-in test-apks-compare-self test-apks-copy

all: apksigcopier.1

install:
	$(PYTHON) -mpip install -e .

test: test-cli doctest lint lint-extra

test-cli:
	# TODO
	apksigcopier --version

doctest:
	# NB: uses test/apks/apks/*.apk
	$(PYTHON) -m doctest apksigcopier/__init__.py

coverage:
	# NB: uses test/apks/apks/*.apk & modifies .tmp
	mkdir -p .tmp/meta
	$(PYCOV) -m doctest apksigcopier/__init__.py
	$(PYCOVCLI) extract test/apks/apks/golden-aligned-v1v2v3-out.apk .tmp/meta
	$(PYCOVCLI) patch .tmp/meta test/apks/apks/golden-aligned-in.apk .tmp/patched.apk
	$(PYCOVCLI) copy test/apks/apks/golden-aligned-v1v2v3-out.apk \
	                 test/apks/apks/golden-aligned-in.apk .tmp/copied.apk
	$(PYCOVCLI) compare test/apks/apks/golden-aligned-v1v2v3-out.apk \
	         --unsigned test/apks/apks/golden-aligned-in.apk
	apksigner verify --verbose .tmp/patched.apk
	apksigner verify --verbose .tmp/copied.apk
	$(PYTHON) -mcoverage html
	$(PYTHON) -mcoverage report

test-apks: test-apks-compare-in test-apks-compare-self test-apks-copy

test-apks-compare-in:
	cd test && ./test-compare-in.sh

test-apks-compare-self:
	cd test && diff -Naur test-compare-self.out <( ./test-compare-self.sh \
	  | sed -r 's!/tmp/[^/]*/!/tmp/.../!' \
	  | sed -r 's!Expected: <[0-9a-f]+>, actual: <[0-9a-f]+>!Expected: <...>, actual: <...>!' )

test-apks-copy:
	cd test && diff -Naur test-copy.out <( $(PYTHON) ./test-copy.py )

lint:
	flake8 apksigcopier/__init__.py
	pylint apksigcopier/__init__.py

lint-extra:
	mypy --strict --disallow-any-unimported apksigcopier/__init__.py

clean: cleanup
	rm -fr apksigcopier.egg-info/

cleanup:
	find -name '*~' -delete -print
	rm -fr __pycache__/ .mypy_cache/
	rm -fr build/ dist/
	rm -fr .coverage htmlcov/
	rm -fr apksigcopier.1
	rm -fr .tmp/

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
