# Use an official Python runtime as a parent image
FROM python:3.12-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file to the working directory
COPY requirements.txt /app/requirements.txt

# Install any required dependencies
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy the current directory contents into the container at /app
COPY . /app

# Copy the .env file into the container
COPY .env /app/.env

# Expose port 5000 for Flask
EXPOSE 5000

# Copy SSL certificates
COPY cert.pem /app/cert.pem
COPY key.pem /app/key.pem

# Run the Flask app
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000", "--cert=cert.pem", "--key=key.pem"]
