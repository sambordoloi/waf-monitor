FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY config.py log_parse.py state.py waf_client.py waf_logs.py waf_log_common.py elk_client.py local_log_client.py token_log_client.py notify.py monitor.py ./

RUN useradd -m appuser && mkdir -p /data && chown appuser:appuser /data
USER appuser

ENV STATE_FILE=/data/state.json
ENV MONITOR_INTERVAL=60

CMD ["python", "-u", "monitor.py"]
