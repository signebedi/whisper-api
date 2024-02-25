#!/bin/bash

# Define the path of the trigger file
RESTART_TRIGGER_FILE="/opt/flask/instance/.reload_triggered"

# Check if an environment argument is provided
if [ -z "$1" ]; then
    echo "$(date) - No environment argument provided." | tee -a /opt/flask/instance/log/reload_manager.log
    exit 1
fi

# Check if the restart trigger file exists
if [ ! -f "$RESTART_TRIGGER_FILE" ]; then
    echo "$(date) - Restart trigger file not found, no action taken." | tee -a /opt/flask/instance/log/reload_manager.log
    exit 0
fi

# Get the environment from the arguments
ENV=$1

# Define service names based on the environment argument
GUNICORN_SERVICE="${ENV}-flask-gunicorn.service"
CELERY_SERVICE="${ENV}-flask-celery.service"
CELERYBEAT_SERVICE="${ENV}-flask-celerybeat.service"

# Function to reload a service if it exists
reload_service() {
    if systemctl --quiet is-active $1; then
        systemctl reload $1
        echo "$(date) - $1 reloaded successfully" | tee -a /opt/flask/instance/log/reload_manager.log
    else
        echo "$(date) - $1 is not active or does not exist" | tee -a /opt/flask/instance/log/reload_manager.log
    fi
}


# Function to restart a service if it exists
restart_service() {
    if systemctl --quiet is-active $1; then
        systemctl restart $1
        echo "$(date) - $1 restarted successfully" | tee -a /opt/flask/instance/log/reload_manager.log
    else
        echo "$(date) - $1 is not active or does not exist" | tee -a /opt/flask/instance/log/reload_manager.log
    fi
}

# Reload services
# reload_service $GUNICORN_SERVICE
# Celery is a bit of a strange beast, so we are just going to
# restart these, see https://github.com/signebedi/gita-api/issues/105.
# reload_service $CELERY_SERVICE
# reload_service $CELERYBEAT_SERVICE
restart_service $GUNICORN_SERVICE
restart_service $CELERY_SERVICE
restart_service $CELERYBEAT_SERVICE


# Remove the restart trigger file
rm -f "$RESTART_TRIGGER_FILE"
echo "$(date) - Reload trigger file removed." | tee -a /opt/flask/instance/log/reload_manager.log