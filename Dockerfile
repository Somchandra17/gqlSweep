FROM python:3.9-slim

WORKDIR /app

# Install curl (useful for debugging/manual requests inside container)
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Copy tool files
COPY gqlsweep.py .
COPY request.curl .
COPY README.md .

# Ensure executable permissions
RUN chmod +x gqlsweep.py

# Create volume mount point for reports
VOLUME /app/reports

# Set entrypoint
ENTRYPOINT ["python3", "gqlsweep.py"]

# Default command shows help
CMD ["--help"]
