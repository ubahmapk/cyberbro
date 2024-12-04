# Use the official Python image from the Docker Hub, version 3.11-slim
FROM python:3.11-slim

# Set the working directory inside the container to /app
WORKDIR /app

# Copy the requirements.txt file from the host to the container
COPY requirements.txt .

# Install the Python dependencies specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt --trusted-host=pypi.python.org --trusted-host=pypi.org --trusted-host=files.pythonhosted.org

# Update the package list and install Supervisor, then clean up the apt cache
RUN apt-get update && \
    apt-get install -y supervisor && \
    rm -rf /var/lib/apt/lists/*

# Copy the rest of the application code from the host to the container
COPY . .

# Expose port 5000 to allow external access to the application
EXPOSE 5000

# Copy the Supervisor configuration file to the appropriate directory
COPY prod/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Start Supervisor using the specified configuration file
CMD ["supervisord", "-c", "/etc/supervisor/supervisord.conf"]