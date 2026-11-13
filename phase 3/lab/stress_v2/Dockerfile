FROM cnet-benign-tools:development
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /stress
COPY network.py client.py capture.py /stress/
ENV PYTHONUNBUFFERED=1
