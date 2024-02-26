import os, shutil
from dotenv import (
    load_dotenv, 
    dotenv_values, 
    set_key
)
from datetime import timedelta, datetime
from markupsafe import Markup
from utils.scripts import check_configuration_assumptions
from flask import flash

# Determine environment
env = os.getenv('FLASK_ENV', 'development')

if not env == 'testing':
    env_file = 'prod.env' if env == 'production' else 'dev.env'
    env_file_path = os.path.join(os.getcwd(), 'instance', env_file)

    if os.path.exists(env_file_path):
        load_dotenv(env_file_path)

    else:
        print("Error: env file not found. Did you run 'app-init config'?")
        exit(1)

else: env_file_path=""

class Config(object):
    ENVIRONMENT = env
    CONFIG_FILE_PATH = env_file_path
    SITE_NAME = os.getenv('SITE_NAME', 'Whisper STT API')
    SITE_SOURCE_URL = os.getenv('SITE_SOURCE_URL', 'https://github.com/signebedi/whisper-api')
    HOMEPAGE_CONTENT = Markup(os.getenv('HOMEPAGE_CONTENT', '<p>This API provides users with programmatic and webpage-based access to the Whisper API. We ask you to register an account to help us understand usage trends, prevent abuse of the API, and meet generally-accepted best practices for API design. Beyond your email, we will not ask you for any personal information, nor provide any of this information to commercial third parties.</p>'))
    DOMAIN = os.getenv('DOMAIN', 'http://127.0.0.1:5000')
    DEBUG = os.getenv('DEBUG', 'False') == 'True'
    SECRET_KEY = os.getenv('SECRET_KEY', 'supersecret_dev_key')
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI', f'sqlite:///{os.path.join(os.getcwd(), "instance", "app.sqlite")}')
    SQLALCHEMY_TRACK_MODIFICATIONS = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS', 'False') == 'True'
    
    HCAPTCHA_ENABLED = os.getenv('HCAPTCHA_ENABLED', 'False') == 'True'
    HCAPTCHA_SITE_KEY = os.getenv('HCAPTCHA_SITE_KEY', "")
    HCAPTCHA_SECRET_KEY = os.getenv('HCAPTCHA_SECRET_KEY', "")

    SMTP_ENABLED = os.getenv('SMTP_ENABLED', 'False') == 'True'
    SMTP_MAIL_SERVER = os.getenv('SMTP_MAIL_SERVER', "")
    SMTP_PORT = int(os.getenv('SMTP_PORT', 25))    
    SMTP_USERNAME = os.getenv('SMTP_USERNAME', "")
    SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', "")
    SMTP_FROM_ADDRESS = os.getenv('SMTP_FROM_ADDRESS', "")

    CELERY_ENABLED = os.getenv('CELERY_ENABLED', 'False') == 'True'
    CELERY_CONFIG = {
        'broker_url': os.getenv('CELERY_BROKER_URL', "pyamqp://guest@localhost//"),
        'result_backend': os.getenv('CELERY_RESULT_BACKEND', "rpc://"),
        'task_serializer': 'json',
        'accept_content': ['json'],
        'result_serializer': 'json',
        'enable_utc': True,
        'broker_connection_retry_on_startup': False,
        # Schedule for periodic tasks
        'beat_schedule':{
            "run-key-check": {
                "task": "app.check_key_rotation",
                # 'schedule': 45.0,  # For rapid testing
                'schedule': 3600.0,  # Hourly
                # 'schedule': 86400.0,  # Daily
            }
        },

    }

    RATE_LIMITS_ENABLED = os.getenv('RATE_LIMITS_ENABLED', 'False') == 'True'
    # Rate limiting period should be an int corresponding to the number of minutes
    RATE_LIMITS_PERIOD = timedelta(minutes=int(os.getenv('RATE_LIMITS_PERIOD', 1)))
    RATE_LIMITS_MAX_REQUESTS = int(os.getenv('RATE_LIMITS_MAX_REQUESTS', 10))

    # MAX_LOGIN_ATTEMPTS = lambda: default_get_max_login_attempts("False")
    MAX_LOGIN_ATTEMPTS = int(os.getenv('MAX_LOGIN_ATTEMPTS', "0"))
    REQUIRE_EMAIL_VERIFICATION = os.getenv('REQUIRE_EMAIL_VERIFICATION', 'False') == 'True'
    # Permanent session lifetime should be an int corresponding to the number of minutes
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=int(os.getenv('PERMANENT_SESSION_LIFETIME', 360)))
    COLLECT_USAGE_STATISTICS = os.getenv('COLLECT_USAGE_STATISTICS', 'False') == 'True'
    DISABLE_NEW_USERS = os.getenv('DISABLE_NEW_USERS', 'False') == 'True'

    # Set help page information
    HELP_PAGE_ENABLED = os.getenv('HELP_PAGE_ENABLED', 'False') == 'True'
    HELP_EMAIL = os.getenv('HELP_EMAIL', "")

    # Set site cookie configs, see https://github.com/signebedi/gita-api/issues/109
    SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'False') == 'True'
    SESSION_COOKIE_SAMESITE = os.getenv('SESSION_COOKIE_SAMESITE', "None")

class ProductionConfig(Config):
    # The DOMAIN is meant to fail in production if you have not set it
    DOMAIN = os.getenv('DOMAIN', None)

    # Defaults to True in production
    HCAPTCHA_ENABLED = os.getenv('HCAPTCHA_ENABLED', 'True') == 'True'
    HCAPTCHA_SITE_KEY = os.getenv('HCAPTCHA_SITE_KEY', None)
    HCAPTCHA_SECRET_KEY = os.getenv('HCAPTCHA_SECRET_KEY', None)
    
    # Defaults to True in production
    SMTP_ENABLED = os.getenv('SMTP_ENABLED', 'False') == 'True'

    # Defaults to True in production
    CELERY_ENABLED = os.getenv('CELERY_ENABLED', 'True') == 'True'

    # Defaults to True / Enabled in production, with more stringent default settings
    RATE_LIMITS_ENABLED = os.getenv('RATE_LIMITS_ENABLED', 'True') == 'True'
    RATE_LIMITS_PERIOD = timedelta(minutes=int(os.getenv('RATE_LIMITS_PERIOD', 60)))
    RATE_LIMITSSMTP_PASSWORD_MAX_REQUESTS = int(os.getenv('RATE_LIMITS_MAX_REQUESTS', 100))

    # MAX_LOGIN_ATTEMPTS = lambda: default_get_max_login_attempts(5)
    MAX_LOGIN_ATTEMPTS = int(os.getenv('MAX_LOGIN_ATTEMPTS', "5")) 
    REQUIRE_EMAIL_VERIFICATION = os.getenv('REQUIRE_EMAIL_VERIFICATION', 'True') == 'True'

    # Set site cookie configs, see https://github.com/signebedi/gita-api/issues/109
    SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'True') == 'True'
    SESSION_COOKIE_SAMESITE = os.getenv('SESSION_COOKIE_SAMESITE', "None")


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{os.path.join(os.getcwd(), "instance", "DEV_app.sqlite")}'

class TestingConfig(Config):
    TESTING = True
    DOMAIN = 'http://127.0.0.1:5000'
    SECRET_KEY = 'supersecret_test_key'
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    HCAPTCHA_ENABLED = False
    SMTP_ENABLED = False

    CELERY_ENABLED = False

    RATE_LIMITS_ENABLED = True
    MAX_LOGIN_ATTEMPTS = False
    REQUIRE_EMAIL_VERIFICATION = False
    PERMANENT_SESSION_LIFETIME = timedelta(hours=int(os.getenv('PERMANENT_SESSION_LIFETIME', 6)))



# View functions should pass config changes as kwargs to the function below
def validate_and_write_configs(app_config, **kwargs):


    # First check assumptions

    app_config_copy = app_config.copy()
    for key in kwargs.keys():
        app_config_copy[key] = kwargs[key]

    try:
        assert check_configuration_assumptions(config=app_config_copy)

    except Exception as e:
        flash (f"{e}", 'warning')
        return

    config_file_path = app_config['CONFIG_FILE_PATH']
    
    # Ensure the .env file exists
    if not os.path.isfile(config_file_path):
        print(f"The file at {config_file_path} does not exist. Creating a new one.")
        with open(config_file_path, 'w'): pass
    else:
        datetime_format = datetime.now().strftime("%Y%m%d%H%M%S") # This can be adjusted as needed
        backup_file_path = f"{config_file_path}.{datetime_format}"
        shutil.copy(config_file_path, backup_file_path)
        print(f"Backup of the current config file created at {backup_file_path}")

    # Load current configurations from .env file
    current_configs = dotenv_values(config_file_path)
    
    for config_name, config_value in kwargs.items():
        if config_name not in app_config.keys():
            print(f"{config_name} not found in app config.")
            continue

        # Convert boolean values to strings to ensure compatibility with .env files
        config_value_str = str(config_value)

        # First we check if the config exists in the config file
        if current_configs.get(config_name) != config_value_str:

            # Then we check if the config is set this way in the app
            # config (if we reach this stage, it effectively means we
            # are in default values territory)
            if app_config[config_name] != config_value:

                # This function updates the .env file directly
                set_key(config_file_path, config_name, config_value_str)
                print(f"Updated {config_name} in .env file.")