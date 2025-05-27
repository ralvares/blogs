FROM quay.myorg.com/approved/python:3.11 AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

FROM quay.myorg.com/approved/python:3.11 AS final
WORKDIR /app
COPY --from=builder /app /app
COPY . /app
CMD ["python", "main.py"]
