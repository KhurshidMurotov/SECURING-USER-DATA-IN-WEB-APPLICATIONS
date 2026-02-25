.PHONY: help install migrate run test clean

help:
	@echo "Available commands:"
	@echo "  make install    - Install dependencies"
	@echo "  make migrate    - Run database migrations"
	@echo "  make run        - Start development server"
	@echo "  make test       - Run tests"
	@echo "  make clean      - Clean Python cache files"

install:
	pip install -r requirements.txt

migrate:
	python manage.py migrate

run:
	python manage.py runserver

test:
	python manage.py test

clean:
	find . -type d -name __pycache__ -exec rm -r {} +
	find . -type f -name "*.pyc" -delete
