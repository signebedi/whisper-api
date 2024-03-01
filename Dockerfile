# Use an official Python runtime as a parent image
FROM python:3.8

# Set the working directory in the container
WORKDIR /

COPY requirements/base.txt requirements.txt

# Install any needed packages specified in requirements/base.txt
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

# Create instance dir
RUN mkdir -p /instance

# Create a empty env files
RUN touch /instance/prod.env
RUN touch /instance/dev.env

# Download model
# RUN python -c "from fw import model"


# Make port 5000 available to the world outside this container
EXPOSE 5000

# Run flask run when the container launches
CMD ["flask", "run", "--host", "0.0.0.0"]
