"""
app-init/__main__.py: a command line utility for Flask app initialization 
Copyright (C) 2024 Sig Janoska-Bedi

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import os, sys
import click
import secrets
import subprocess
import tempfile
from datetime import datetime
from typing import Union
from dotenv import set_key
from werkzeug.security import generate_password_hash

# Add the project root to the python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)

__version__ = "1.0.0"
__author__ = "Sig Janoska-Bedi"
__credits__ = ["Sig Janoska-Bedi"]
__license__ = "AGPL-3.0"
__maintainer__ = "Sig Janoska-Bedi"
__email__ = "signe@atreeus.com"


# Creating a Click group
@click.group()
def cli():
    pass

# Helper function for boolean prompts
def prompt_bool(message, default=None):
    """
    Prompt for a boolean value, interpreting 'y' as True and 'n' as False.
    """
    while True:
        default_str = 'y' if default else 'n'
        value = click.prompt(f"{message} (y/n)", default=default_str, type=str).lower()
        if value in ['y', 'yes']:
            return True
        elif value in ['n', 'no']:
            return False
        else:
            click.echo("Please enter 'y' for yes or 'n' for no.")

@cli.command('config')
@click.argument('env_type', type=click.Choice(['prod', 'dev'], case_sensitive=False))
@click.option('--domain', default=None, help='Domain of the application')
@click.option('--site-name', default=None, help='Site name of the application')
# @click.option('--debug', default=None, type=bool, help='Enable or disable debug mode')
@click.option('--secret-key', default=None, help='Secret key for the application')
@click.option('--sqlalchemy-database-uri', default=None, help='Database URI for SQLAlchemy')
@click.option('--hcaptcha-enabled', default=None, type=bool, help='Enable hCaptcha')
@click.option('--smtp-enabled', default=None, type=bool, help='Enable SMTP')
@click.option('--celery-enabled', default=None, type=bool, help='Enable Celery')
@click.option('--rate-limits-enabled', default=None, type=bool, help='Enable rate limits')
@click.option('--rate-limits-max-requests', default=100, type=int, help='Maximum requests allowed in the rate limit period')
@click.option('--rate-limits-period', default=60, type=int, help='Time frame (in minutes) for rate limiting')
@click.option('--max-login-attempts', default=None, type=None, help='Enable maximum login attempts (0 will disable)')
@click.option('--require-email-verification', default=None, type=bool, help='Require email verification')
@click.option('--smtp-mail-server', default=None, help='SMTP Mail Server')
@click.option('--smtp-port', default=None, type=int, help='SMTP Port')
@click.option('--smtp-username', default=None, help='SMTP Username')
@click.option('--smtp-password', default=None, help='SMTP Password')
@click.option('--smtp-from-address', default=None, help='SMTP From Address')
@click.option('--hcaptcha-site-key', default=None, help='hCaptcha Site Key')
@click.option('--hcaptcha-secret-key', default=None, help='hCaptcha Secret Key')
@click.option('--permanent-session-lifetime', default=360, type=int, help='Length of user sessions in minutes')
@click.option('--disable-new-users', default=False, type=bool, help='Prevent new users from registering accounts')
@click.option('--collect-usage-statistics', default=False, type=bool, help='Collect API usage statistics')
def init_app_command(env_type, domain, site_name, secret_key, sqlalchemy_database_uri, 
                        hcaptcha_enabled, smtp_enabled, celery_enabled, rate_limits_enabled, 
                        rate_limits_period, rate_limits_max_requests, max_login_attempts, 
                        require_email_verification, smtp_mail_server, smtp_port, smtp_username, 
                        smtp_password, smtp_from_address, hcaptcha_site_key, hcaptcha_secret_key,
                        permanent_session_lifetime, disable_new_users, collect_usage_statistics):

    if env_type.lower() == 'prod':
        env_file = os.path.join(os.getcwd(), 'instance', 'prod.env')
    else:
        env_file = os.path.join(os.getcwd(), 'instance', 'dev.env')

    # Ensure the instance folder exists
    try:
        os.makedirs(os.path.join(os.getcwd(), 'instance'))
    except OSError:
        pass

    # Ensure both prod.env and dev.env files exist
    for file in ['prod.env', 'dev.env']:
        try:
            open(os.path.join(os.getcwd(), 'instance', file), 'a').close()
        except OSError:
            pass    
        

    # Generate a secret key if not provided
    if not secret_key:
        secret_key = secrets.token_urlsafe(16)

    # Basic configurations
    config = {
        'DOMAIN': domain if domain is not None else click.prompt('Enter DOMAIN', default='http://127.0.0.1:5000'),
        'SITE_NAME': site_name if site_name is not None else click.prompt('Enter SITE_NAME', default='Flask API'),
        'SECRET_KEY': secret_key,
        'SQLALCHEMY_DATABASE_URI': sqlalchemy_database_uri if sqlalchemy_database_uri is not None else click.prompt('What is your database connection string?', default=f"sqlite:///{os.path.join(os.getcwd(), 'instance', 'app.sqlite')}"),
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'HCAPTCHA_ENABLED': hcaptcha_enabled if hcaptcha_enabled is not None else prompt_bool('Is HCAPTCHA enabled?', default=False),
        'SMTP_ENABLED': smtp_enabled if smtp_enabled is not None else prompt_bool('Is SMTP enabled?', default=False),
        'CELERY_ENABLED': celery_enabled if celery_enabled is not None else prompt_bool('Is CELERY enabled?', default=False),
        'RATE_LIMITS_ENABLED': rate_limits_enabled if rate_limits_enabled is not None else prompt_bool('Is RATE LIMITS enabled?', default=False),
        'RATE_LIMITS_PERIOD': rate_limits_period,
        'RATE_LIMITS_MAX_REQUESTS': rate_limits_max_requests,
        'REQUIRE_EMAIL_VERIFICATION': require_email_verification if require_email_verification is not None else prompt_bool('Is REQUIRE EMAIL VERIFICATION enabled?', default=False),
        'PERMANENT_SESSION_LIFETIME': permanent_session_lifetime,
        'DISABLE_NEW_USERS': disable_new_users,
        'COLLECT_USAGE_STATISTICS': collect_usage_statistics,
    }

    if max_login_attempts is None:
        enable_max_login_attempts = prompt_bool('Is MAX LOGIN ATTEMPTS enabled?', default=False)

    if enable_max_login_attempts:
        max_login_attempts = click.prompt('How many MAX LOGIN ATTEMPTS?', default=3)
    else:
        max_login_attempts = 0
    
    config['MAX_LOGIN_ATTEMPTS'] = max_login_attempts

    # Additional configurations based on enabled features
    if config['HCAPTCHA_ENABLED']:
        config['HCAPTCHA_SITE_KEY'] = hcaptcha_site_key if hcaptcha_site_key is not None else click.prompt('Enter hCaptcha site key')
        config['HCAPTCHA_SECRET_KEY'] = hcaptcha_secret_key if hcaptcha_secret_key is not None else click.prompt('Enter hCaptcha secret key')
    
    if config['SMTP_ENABLED']:
        config['SMTP_MAIL_SERVER'] = smtp_mail_server if smtp_mail_server is not None else click.prompt('Enter SMTP mail server')
        config['SMTP_PORT'] = smtp_port if smtp_port is not None else click.prompt('Enter SMTP port', type=int)
        config['SMTP_USERNAME'] = smtp_username if smtp_username is not None else click.prompt('Enter SMTP username')
        config['SMTP_PASSWORD'] = smtp_password if smtp_password is not None else click.prompt('Enter SMTP password', hide_input=True)
        config['SMTP_FROM_ADDRESS'] = smtp_from_address if smtp_from_address is not None else click.prompt('Enter SMTP from address')

    # Run an assumptions check against the information passed and quit if assumptions are broken
    from utils.scripts import check_configuration_assumptions
    assert check_configuration_assumptions(config=config)

    # Write configurations to .env
    for key, value in config.items():
        set_key(env_file, key, str(value))

    click.echo(f"Configurations have been set. You can find them at {env_file}.")


def create_user_and_group(user, group):
    # Check if group exists
    if subprocess.run(['getent', 'group', group]).returncode != 0:
        try:
            subprocess.run(['sudo', 'groupadd', group], check=True)
        except subprocess.CalledProcessError:
            click.echo(f"Group '{group}' already exists or could not be created.")

    # Check if user exists
    if subprocess.run(['id', user]).returncode != 0:
        try:
            # Use either -m or --no-create-home based on your requirement
            subprocess.run(['sudo', 'useradd', '--no-create-home', '--system', '-g', group, user], check=True)
        except subprocess.CalledProcessError:
            click.echo(f"User '{user}' already exists or could not be created.")


def change_ownership(path, user, group):
    try:
        subprocess.run(['sudo', 'chown', '-R', f'{user}:{group}', path], check=True)
    except subprocess.CalledProcessError:
        click.echo(f"Failed to change ownership of {path}.")

@cli.command('gunicorn')
@click.option('--user', default='flask', help='User for the systemd service')
@click.option('--group', default='flask', help='Group for the systemd service')
@click.option('--environment', default='production', type=click.Choice(['production', 'development']), help='Environment for the systemd service')
@click.option('--working-directory', default=os.getcwd(), help='Working directory for the systemd service')
@click.option('--environment-path', default=os.path.join(os.getcwd(),'venv','bin'), help='Path for the environment')
@click.option('--gunicorn-config', default=os.path.join(os.getcwd(),'utils', 'gunicorn.conf.py'), help='Gunicorn configuration file')
@click.option('--start-on-success', is_flag=True, help='Start and enable NGINX configuration on success')
def init_gunicorn_command(user, group, environment, working_directory, environment_path, gunicorn_config, start_on_success):

    systemd_unit = f"""
[Unit]
Description={environment} flask gunicorn daemon
After=network.target

[Service]
User={user}
Group={group}
WorkingDirectory={working_directory}
Environment='FLASK_ENV={environment}'
Environment='PATH={environment_path}'
ExecStart={environment_path}/gunicorn 'wsgi:app' --config {gunicorn_config}
ExecReload=/bin/kill -HUP $MAINPID

[Install]
WantedBy=multi-user.target
"""
    # click.echo(systemd_unit)
    service_name = f"{environment}-flask-gunicorn.service"
    unit_file_path = f'/etc/systemd/system/{service_name}'
    # click.echo(unit_file_path)

    # Write the systemd unit content to a temporary file
    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        tmp_file.write(systemd_unit.encode())
        temp_path = tmp_file.name

    # Move the temporary file to the systemd directory
    os.system(f"sudo mv {temp_path} {unit_file_path}")

    os.system('sudo systemctl daemon-reload')

    create_user_and_group(user, group)
    change_ownership(working_directory, user, group)

    if start_on_success:
        os.system(f'sudo systemctl start {service_name}')
        os.system(f'sudo systemctl enable {service_name}')

    click.echo("Systemd unit file for flask has been created and daemon reloaded.")
    click.echo("Use the following commands to start and enable the service:")
    click.echo(f"sudo systemctl start {service_name}")
    click.echo(f"sudo systemctl enable {service_name}")
    if start_on_success:
        click.echo(f"{service_name} has been started and enabled.")

    # If we are using gunicorn, then also want to start a CRON job that will help with 
    # automatic service reload, see https://github.com/signebedi/gita-api/issues/83.

    # Define the path to the script you want to make executable
    script_path = os.path.join(of.getcwd(),"utils","flask_reload_manager.sh")
    
    # Make the script executable using chmod +x
    try:
        subprocess.run(['chmod', '+x', script_path], check=True)
        click.echo(f"Successfully made {script_path} executable.")
    except subprocess.CalledProcessError as e:
        click.echo(f"Failed to make {script_path} executable: {e}")


    # Define an environment-specific CRON job
    new_cron_job = f"*/5 * * * * {script_path} {environment}"

    # Append new CRON job to root's crontab, see https://stackoverflow.com/a/16068840/13301284.
    append_cron_job_cmd = f'(crontab -l 2>/dev/null; echo "{new_cron_job}") | crontab -'

    # Execute the command as root
    try:
        subprocess.run(['sudo', 'bash', '-c', append_cron_job_cmd], check=True)
        click.echo("Successfully created automated-restart CRON job.")
    except subprocess.CalledProcessError as e:
        click.echo(f"Failed to create automated-restart CRON job: {e}")


@cli.command('celery')
@click.option('--user', default='flask', help='User for the systemd service')
@click.option('--group', default='flask', help='Group for the systemd service')
@click.option('--environment', default='production', type=click.Choice(['production', 'development', 'testing']), help='Environment for the systemd service')
@click.option('--working-directory', default=os.getcwd(), help='Working directory for the systemd service')
@click.option('--environment-path', default=os.path.join(os.getcwd(), 'venv', 'bin'), help='Path for the environment')
@click.option('--start-on-success', is_flag=True, help='Start and enable Celery configuration on success')
def init_celery_command(user, group, environment, working_directory, environment_path, start_on_success):
    # Celery worker unit content
    celery_worker_unit = f"""
[Unit]
Description={environment} flask celery daemon
After=network.target

[Service]
Type=simple
User={user}
Group={group}
WorkingDirectory={working_directory}
Environment='FLASK_ENV={environment}'
Environment='PATH={environment_path}'
ExecStart={environment_path}/celery -A app.celery worker --loglevel=info --logfile {working_directory}/instance/log/celery.log
Restart=always

[Install]
WantedBy=multi-user.target
"""

    # Celery beat unit content
    celery_beat_unit = f"""
[Unit]
Description={environment} flask celerybeat daemon
After=network.target

[Service]
Type=simple
User={user}
Group={group}
WorkingDirectory={working_directory}
Environment='FLASK_ENV={environment}'
Environment='PATH={environment_path}'
ExecStart={environment_path}/celery -A app.celery beat --loglevel=info --logfile {working_directory}/instance/log/beat.log
Restart=always

[Install]
WantedBy=multi-user.target
"""

    # Write the unit files
    worker_service_name = f"{environment}-flask-celery.service"
    worker_file_path = f'/etc/systemd/system/{worker_service_name}'
    
    beat_service_name = f"{environment}-flask-celerybeat.service"
    beat_file_path = f'/etc/systemd/system/{beat_service_name}'

    with open(worker_file_path, 'w') as worker_file:
        worker_file.write(celery_worker_unit)

    with open(beat_file_path, 'w') as beat_file:
        beat_file.write(celery_beat_unit)

    click.echo("Celery worker and beat systemd unit files have been created.")

    # Reload systemd daemons
    os.system('sudo systemctl daemon-reload')
    click.echo("Systemd daemon reloaded.")

    if start_on_success:
        # Start and enable the Celery worker service
        os.system(f'sudo systemctl start {worker_service_name}')
        os.system(f'sudo systemctl enable {worker_service_name}')
        click.echo(f"Celery worker service for {environment} environment started and enabled.")

        # Start and enable the Celery beat service
        os.system(f'sudo systemctl start {beat_service_name}')
        os.system(f'sudo systemctl enable {beat_service_name}')
        click.echo(f"Celery beat service for {environment} environment started and enabled.")




def request_certificates(domain):
    cert_path = f'/etc/letsencrypt/live/{domain}/fullchain.pem'
    key_path = f'/etc/letsencrypt/live/{domain}/privkey.pem'

    # Check if the certificate already exists and is valid
    cert_exists = os.path.isfile(cert_path) and os.path.isfile(key_path)
    if cert_exists:
        # Optionally, you can add more checks here to validate the existing certificate
        print("Certificate already exists.")
        return cert_path, key_path

    # Running certbot to obtain the certificates
    try:
        subprocess.run(['sudo', 'certbot', 'certonly', '--standalone', '-d', domain], check=True)
        return cert_path, key_path
    except subprocess.CalledProcessError as e:
        # Handle errors here
        print(f"Error obtaining certificates: {e}")
        return None, None

@cli.command('nginx')
@click.option('--server-name', prompt='Server name', help='Server name for NGINX')
@click.option('--ssl-enabled', is_flag=True, help='Enable SSL configuration')
@click.option('--request-certbot-certs', is_flag=True, help='Request SSL certificates from Let\'s Encrypt')
@click.option('--ssl-cert-path', default='/etc/ssl/certs/nginx-selfsigned.crt', help='Path to the SSL certificate (ignored if --request-certbot-certs is set)')
@click.option('--ssl-cert-key-path', default='/etc/ssl/private/nginx-selfsigned.key', help='Path to the SSL certificate key (ignored if --request-certbot-certs is set)')
@click.option('--http-port', default=80, help='HTTP port for NGINX (default: 80)')
@click.option('--https-port', default=443, help='HTTPS port for NGINX (default: 443)')
@click.option('--app-port', default=8000, help='Port where the app is running (default: 8000)')
@click.option('--app-ip', default='0.0.0.0', help='IP address of the app (default: 0.0.0.0)')
@click.option('--start-on-success', is_flag=True, help='Start and enable NGINX configuration on success')
@click.option('--retain-default', is_flag=True, help="Retain the default NGINX config in sites-enabled")
def init_nginx_command(server_name, ssl_enabled, request_certbot_certs, ssl_cert_path, ssl_cert_key_path, http_port, https_port, app_port, app_ip, start_on_success, retain_default):
    """
    Note that you will need certbot installed if installing SSL/TLS certificates at runtime.
    """

    if request_certbot_certs:
        ssl_cert_path = f'/etc/letsencrypt/live/{server_name}/fullchain.pem'
        ssl_cert_key_path = f'/etc/letsencrypt/live/{server_name}/privkey.pem'
        subprocess.run(['sudo', 'certbot', 'certonly', '--standalone', '-d', server_name])

    nginx_config = f"""
# Default server block for handling unmatched domain requests on port 80
server {{
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 444;  # This will close the connection without responding
}}

upstream app_server {{
    server {app_ip}:{app_port};
}}

# Server block for handling HTTP requests
server {{
    listen                      {http_port};
    listen                      [::]:{http_port};
    server_name                 {server_name};

    {'return 301 https://$server_name$request_uri;' if ssl_enabled else '''
    location / {
        proxy_pass http://app_server;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }'''
    }
}}
"""

    # Additional server block for handling HTTPS requests, if SSL is enabled
    if ssl_enabled:
        nginx_config += f"""
# Default server block for handling unmatched domain requests on port 443
server {{
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;
    ssl_certificate             {ssl_cert_path};
    ssl_certificate_key         {ssl_cert_key_path};
    return 444;  # This will close the connection without responding
}}

# Server block for handling HTTPS requests
server {{
    listen                      {https_port} ssl;
    listen                      [::]:{https_port} ssl;
    server_name                 {server_name};

    ssl_certificate             {ssl_cert_path};
    ssl_certificate_key         {ssl_cert_key_path};

    location / {{
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Server $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_redirect off;
        proxy_pass http://app_server;
    }}
}}
"""


    # Write the NGINX configuration to a temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix='.conf') as tmp_file:
        tmp_file.write(nginx_config.encode())
        temp_path = tmp_file.name

    # Move the temporary file to the NGINX configuration directory
    nginx_conf_path = f'/etc/nginx/sites-available/{server_name}'
    os.system(f'sudo mv {temp_path} {nginx_conf_path}')
    os.system(f'sudo ln -s {nginx_conf_path} /etc/nginx/sites-enabled/')

    # Remove default NGINX configuration unless --retain-default is passed
    if not retain_default:
        default_config_path = '/etc/nginx/sites-enabled/default'
        if os.path.exists(default_config_path):
            os.system('sudo rm ' + default_config_path)
            click.echo("Default NGINX configuration removed.")
        else:
            click.echo("No default NGINX configuration found to remove.")

    if start_on_success:
        os.system('sudo nginx -t && sudo systemctl restart nginx')
        os.system('sudo systemctl enable nginx')

    click.echo("NGINX configuration file has been created.")
    click.echo(f"Configuration file path: {nginx_conf_path}")
    if start_on_success:
        click.echo("NGINX has been restarted and enabled.")


@cli.command('useradd')
@click.option('--username', prompt=True, help='Username of the new user')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='Password for the new user')
@click.option('--email', prompt=True, help='Email of the new user')
@click.option('--opt-out', is_flag=True, help='Opt out of usage statistics')
@click.option('--site-admin', is_flag=True, help='Set this user as a site admin')
@click.option('--environment', type=click.Choice(['development', 'production'], case_sensitive=False), default='production', help='Set the environment (important if you use different databases for dev and prod).')
def add_user_command(username, password, email, opt_out, site_admin, environment):
    """Add a new user to the application."""

    # Set FLASK_ENV
    os.environ['FLASK_ENV'] = environment
    from app import app, db, User, signatures

    with app.app_context():
        # Check if user or email already exists
        existing_user = User.query.filter(User.username.ilike(username)).first()
        if existing_user:
            click.echo(f"Username {username} is already registered.")
            return

        existing_email = User.query.filter(User.email.ilike(email)).first()
        if existing_email:
            click.echo(f"Email {email} is already registered.")
            return

        # Create new user
        new_user = User(
            email=email, 
            username=username.lower(), 
            password=generate_password_hash(password),
            active=app.config["REQUIRE_EMAIL_VERIFICATION"] == False,
            opt_out=opt_out if app.config["COLLECT_USAGE_STATISTICS"] else True,
            site_admin=site_admin,
        )

        # Create the user's API key
        expiration = 365*24 if app.config['CELERY_ENABLED'] else 0
        api_key = signatures.write_key(scope=['api_key'], expiration=expiration, active=True, email=email)
        new_user.api_key = api_key

        # Add user to database
        try:
            db.session.add(new_user)
            db.session.commit()
            click.echo(f"User '{username}' successfully added.")
        except Exception as e:
            click.echo(f"Error adding user: {e}")


@cli.command('usermod')
@click.argument('username')
@click.option('--password', help='New password for the user', default=None)
@click.option('--new-email', help='New email for the user', default=None)
@click.option('--opt-out', type=bool, help='Change opt-out of usage statistics', default=None)
@click.option('--active', type=bool, help='Change active status', default=None)
@click.option('--site-admin', type=bool, help='Change site admin status', default=None)
@click.option('--headless', is_flag=True, help='Run this command headlessly')
@click.option('--environment', type=click.Choice(['development', 'production'], case_sensitive=False), default='production', help='Set the environment (important if you use different databases for dev and prod).')
def modify_user_command(username, password, new_email, opt_out, active, site_admin, headless, environment):
    """Modify an existing user in the application."""

    # Set FLASK_ENV
    os.environ['FLASK_ENV'] = environment
    from app import app, db, User, signatures

    with app.app_context():
        user = User.query.filter(User.username.ilike(username)).first()
        if not user:
            click.echo(f"Username {username} does not exist.")
            return

        # Interactively ask for changes if not in headless mode
        if not headless:
            if password is None and click.confirm('Do you want to change the password?'):
                password = click.prompt('Enter new password', hide_input=True, confirmation_prompt=True)

            if new_email is None and click.confirm('Do you want to change the email?'):
                new_email = click.prompt('Enter new email', default=user.email)

            if active is None and click.confirm('Do you want to change user active status?'):
                active = click.confirm('Set user to active')

            if opt_out is None and click.confirm('Do you want to change the opt-out setting?'):
                opt_out = click.confirm('Opt out of usage statistics')

            if site_admin is None and click.confirm('Do you want to change the site admin status?'):
                site_admin = click.confirm('Set as site admin')

        # Check if new email is already registered
        if new_email and new_email != user.email:
            existing_email = User.query.filter(User.email.ilike(new_email)).first()
            if existing_email:
                click.echo(f"Email {new_email} is already registered.")
                return
            user.email = new_email

        # Update other fields if provided
        if password:
            user.password = generate_password_hash(password)

        if active is not None:
            user.active = active

        if opt_out is not None:
            user.opt_out = opt_out

        if site_admin is not None:
            user.site_admin = site_admin

        # Save changes to database
        try:
            db.session.commit()
            click.echo(f"User '{username}' successfully modified.")
        except Exception as e:
            click.echo(f"Error modifying user: {e}")

@cli.command('id')
@click.argument('username')
@click.option('--environment', type=click.Choice(['development', 'production'], case_sensitive=False), default='production', help='Set the environment (important if you use different databases for dev and prod).')
def id_command(username, environment):
    """Display user details for a given username."""

    # Set FLASK_ENV
    os.environ['FLASK_ENV'] = environment
    from app import app, db, User, signatures


    with app.app_context():
        user = User.query.filter(User.username.ilike(username)).first()
        if not user:
            click.echo(f"User with username '{username}' not found.")
            return

        # Formatting the user details
        user_details = (
            f"ID: {user.id}\n"
            f"Username: {user.username}\n"
            f"Email: {user.email}\n"
            f"Active: {user.active}\n"
            f"Created Date: {user.created_date.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Last Login: {user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else 'Never'}\n"
            f"Last Password Change: {user.last_password_change.strftime('%Y-%m-%d %H:%M:%S') if user.last_password_change else 'Never'}\n"
            f"Opt Out: {user.opt_out}\n"
            f"Site Admin: {user.site_admin}"
        )

        click.echo(user_details)




if __name__ == "__main__":
    cli()
