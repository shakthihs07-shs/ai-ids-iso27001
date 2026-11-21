# Scores honeypot flows with the detector's ONNX models (shadow mode). Build context: the repository root,
# so the published models in live/model are used unchanged.
FROM python:3.12-slim
RUN pip install --no-cache-dir onnxruntime==1.32.0
COPY live/model/card.json live/model/supervised.onnx live/model/anomaly.onnx /model/
COPY honeypot/shadow/score.py /app/score.py
USER nobody
ENTRYPOINT ["python", "/app/score.py"]
