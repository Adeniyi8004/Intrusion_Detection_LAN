# Base Image
FROM python:3.9-slim

# Set Working Directory
WORKDIR /usr/src/app

# Install Dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy Python Script and Alert File
COPY snort_processor.py ./
COPY alert_json.txt /var/log/snort/alert_json.txt

# Set Environment Variables
ENV IOTA_URL=http://iot-agent:4061
ENV ORION_URL=http://orion:1026
ENV FIWARE_SERVICE=snortService
ENV FIWARE_SERVICEPATH=/
ENV DEVICE_ID=snortDevice
ENV API_KEY=1234
ENV ALERT_FILE_PATH=/var/log/snort/alert_json.txt

# Execute Python Script
CMD ["python", "./snort_processor.py"]

