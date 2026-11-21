# Live IDS console: FastAPI service + live dashboard (Hugging Face Spaces, Docker SDK, port 7860).
# The image downloads CIC-IDS2017 and trains the detector at build time, so the dataset is
# never redistributed; the raw data is deleted in the same layer.
FROM python:3.15-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl unzip && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 1000 user
USER user
ENV HOME=/home/user PATH=/home/user/.local/bin:$PATH PYTHONUNBUFFERED=1
WORKDIR /home/user/app

COPY --chown=user requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

COPY --chown=user data/download_cicids2017.sh data/
COPY --chown=user src/ src/
COPY --chown=user app/ app/
RUN bash data/download_cicids2017.sh && python -m app.train && rm -rf data/cicids2017

EXPOSE 7860
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "7860"]
