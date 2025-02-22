FROM python:3.9.18-alpine3.18

RUN apk add build-base

RUN apk add postgresql-dev gcc python3-dev musl-dev

ARG FLASK_APP
ARG FLASK_ENV
ARG DATABASE_URL
ARG SCHEMA
ARG SECRET_KEY

WORKDIR /var/www

# Make sure the static directory exists
RUN mkdir -p frontend/dist

COPY requirements.txt .

RUN pip install -r requirements.txt
RUN pip install psycopg2

COPY . .

# Verify the static files exist
RUN ls -la frontend/dist/

RUN flask db upgrade
RUN flask seed all
CMD gunicorn "app:app" 