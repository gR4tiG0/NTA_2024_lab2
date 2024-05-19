FROM python:3.8-slim-buster

WORKDIR /app

RUN apt-get update && apt-get install -y gcc make libgmp-dev

ADD ./labfiles /app

RUN ["make"]
CMD ["python", "./stdserver.py"]