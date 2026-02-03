FROM python:3.11-slim

RUN mkdir -p /app/agent
WORKDIR /app
ENV PYTHONPATH=/app

COPY requirements.txt /requirements.txt
RUN pip install --no-cache-dir -r /requirements.txt

COPY agent /app/agent
COPY oxo.yaml /app/agent/oxo.yaml

WORKDIR /app
CMD ["python3", "/app/agent/nessus_agent.py"]
