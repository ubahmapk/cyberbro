# Use a base Python image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies for Tor
RUN apt-get update && \
    apt-get install -y tor && \
    rm -rf /var/lib/apt/lists/*

# Configure Tor to allow control with cookie authentication
RUN echo "ControlPort 9051\nCookieAuthentication 1" >> /etc/tor/torrc

# Copy the requirements.txt file into the container
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your project files into the container
COPY . .

# Expose port 5000 for Flask and port 9051 for Tor ControlPort
EXPOSE 5000 9051

# Start Tor in the background and then the Flask application
CMD tor & python app.py