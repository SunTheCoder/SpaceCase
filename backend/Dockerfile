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

# Create a script to handle database setup
RUN echo '#!/bin/sh\n\
flask db upgrade\n\
flask seed all\n\
gunicorn "app:app"' > /var/www/start.sh

RUN chmod +x /var/www/start.sh

# Use the script as the entry point
CMD ["/var/www/start.sh"] 