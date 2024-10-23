# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file and the code
COPY requirements.txt .
COPY . .

# Install the required Python packages
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port your application runs on
EXPOSE 5000

# Run the application
CMD ["python", "app.py"]
