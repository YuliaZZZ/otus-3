start:
	python3 -m api -p 8080 -l otus.log

test:
	python3 -m unittest test.py



.PHONY: start test