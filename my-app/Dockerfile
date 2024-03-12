# Use the official Alpine Linux as base image
FROM alpine:latest

# Install OpenJDK 11
RUN apk --no-cache add openjdk11

# Set the working directory in the container
WORKDIR /app

# Create a simple script to run when the container starts
RUN echo "#!/bin/sh" >> /app/run.sh
RUN echo "echo 'Hello, Docker!'" >> /app/run.sh
RUN chmod +x /app/run.sh

# Run the script when the container starts
CMD ["/bin/sh", "/app/run.sh"]
