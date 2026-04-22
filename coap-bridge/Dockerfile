FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY bridge.py .

ENV FASTAPI_BASE_URL=http://nac_api:8000
ENV COAP_BIND_HOST=0.0.0.0
ENV COAP_BIND_PORT=5683
ENV DEFAULT_MESSAGE_TYPE=coap

CMD ["python", "bridge.py"]
