install:
	pip install -U pip
	pip install -e .[tests,docs]

tests:
	pytest --cov=./ --disable-warnings
