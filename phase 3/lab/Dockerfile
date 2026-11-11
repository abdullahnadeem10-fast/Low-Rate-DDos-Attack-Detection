FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends tcpdump \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /lab
COPY client.py capture.py /lab/
ENV PYTHONUNBUFFERED=1
