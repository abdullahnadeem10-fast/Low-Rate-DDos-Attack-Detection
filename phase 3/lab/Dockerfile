FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
RUN apt-get update && apt-get install -y --no-install-recommends tcpdump ethtool \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /lab
COPY client.py capture.py /lab/
ENV PYTHONUNBUFFERED=1
