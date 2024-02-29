# Use an official Python runtime as a parent image
FROM python:3.8

# Set the working directory in the container
WORKDIR /app

COPY requirements/base.txt requirements.txt

# Install any needed packages specified in requirements/base.txt
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

# Create instance dir
RUN mkdir -p /app/instance

# Create a empty env files
RUN touch /app/instance/prod.env
RUN touch /app/instance/dev.env

# Download model
# RUN python3 /app/utils/download_model.py --output_dir /app/instance/ "medium.en"
# ENV WHISPER_MODEL_SIZE=/app/instance/medium

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Run flask run when the container launches
CMD ["flask", "run", "--host", "0.0.0.0"]
