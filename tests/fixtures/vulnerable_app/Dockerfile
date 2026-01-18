# Vulnerable Flask Application
# FOR MRZERO TESTING ONLY - DO NOT DEPLOY

FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# VULNERABLE: Running as root
# VULNERABLE: Debug mode enabled
# VULNERABLE: Binding to all interfaces

EXPOSE 5000

CMD ["python", "app.py"]
