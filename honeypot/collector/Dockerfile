FROM python:3.12-slim
RUN pip install --no-cache-dir fastapi==0.165.0 uvicorn==0.54.0
WORKDIR /app
COPY fetch_geo.py collector.py ./
# Country lookup data, refreshed whenever the image is rebuilt (monthly, see setup-host.sh)
RUN python fetch_geo.py /app/dbip-country-lite.csv.gz \
    && mkdir -p /data /var/log/opencanary && chown nobody:nogroup /data /var/log/opencanary
USER nobody
CMD ["python", "collector.py"]
