FROM python:3.9-slim
LABEL authors="evgen"

RUN apt-get update && apt-get install -y \
    libmagic-dev \
    yara \
    && pip install pyicap yara-python

COPY icap_server.py /app/icap_server.py
CMD ["python", "/app/icap_server.py"]
