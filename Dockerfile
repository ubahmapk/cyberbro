# Use the official Python image from the Docker Hub, version 3.13-slim
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

# Update the package list and install supervisor, then clean up the apt cache
RUN apt-get update && \
    apt-get install -y --no-install-recommends supervisor && \
    rm -rf /var/lib/apt/lists/*

# Create an unprivileged user for runtime execution
RUN groupadd --system cyberbro && \
    useradd --system --gid cyberbro --create-home --home-dir /home/cyberbro --shell /usr/sbin/nologin cyberbro

# Set the working directory inside the container to /app
WORKDIR /app

# Copy the application code from the host to the container
COPY . .

# Install the Python dependencies specified in requirements.txt
RUN uv pip install --system --no-cache-dir -r requirements.txt

# Prepare writable paths and transfer ownership to the non-root user
RUN mkdir -p /var/log/cyberbro /app/data && \
    chown -R cyberbro:cyberbro /app /var/log/cyberbro

# Expose port 5000 to allow external access to the application
EXPOSE 5000

# Give permission to execute prod/entrypoint.sh
RUN chmod +x prod/entrypoint.sh

# Run the application using the entrypoint.sh script
CMD ["./prod/entrypoint.sh"]
