import os


def pre_fork(server, worker):
    from app import app, db 

    with app.app_context():
        # SQLAlchemy's create_all is idempotent and typically doesn't recreate
        # tables that already exist. However, when run in a post-fork environment
        # with multiple workers, such as under Gunicorn, it can behave 
        # unpredictably due to race conditions. Hence, it's safer to run it 
        # before forking worker processes.
        db.create_all()


# Ensure the instance log folder exists
try:
    os.makedirs(os.path.join(os.getcwd(), 'instance', 'log'))
except OSError:
    pass

bind="0.0.0.0:8000"
workers = 3 
logpath='instance/log'
errorlog = os.path.join(logpath, "gunicorn.error")
accesslog = os.path.join(logpath, "gunicorn.access")
loglevel = "debug"