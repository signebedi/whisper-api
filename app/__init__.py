"""
app/__init__.py: a general Flask app with REST and UI
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

import re, os, json, tempfile
import pandas as pd
import plotly
import plotly.express as px
from datetime import datetime, timedelta

from flask import (
    Flask, 
    request, 
    jsonify, 
    Response,
    render_template, 
    url_for,
    current_app,
    flash,
    redirect,
    abort,
    session,
)
from flask_signing import (
    Signatures,
    RateLimitExceeded, 
    KeyDoesNotExist, 
    KeyExpired,
)
from markupsafe import escape
from flask_login import (
    LoginManager, 
    current_user, 
    login_required, 
    UserMixin,
    login_user, 
    logout_user,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import desc

from app.config import (
    DevelopmentConfig, 
    ProductionConfig, 
    TestingConfig,
    validate_and_write_configs,
)

from utils.smtp import Mailer
from utils.celery import make_celery
from utils.scripts import check_configuration_assumptions
from utils.custom_sqlalchemy import SQLAlchemy

from fw import (
    WHISPER_RETAIN_AUDIO,
    WHISPER_RETAIN_TRANSCRIBED_TEXT,
    WHISPER_MODEL_SIZE,
    WHISPER_DEVICE,
    WHISPER_COMPUTE_TYPE,
    transcribe_audio,
)

__version__ = "1.0.0"
__name__ = "app"
__author__ = "Sig Janoska-Bedi"
__credits__ = ["Sig Janoska-Bedi"]
__license__ = "AGPL-3.0"
__maintainer__ = "Sig Janoska-Bedi"
__email__ = "signe@atreeus.com"


app = Flask(__name__)

env = os.environ.get('FLASK_ENV', 'development')
if env == 'production':
    app.config.from_object(ProductionConfig)
elif env == 'testing':
    app.config.from_object(TestingConfig)
else:
    app.config.from_object(DevelopmentConfig)


# Set whisper specfic configs
app.config['WHISPER_RETAIN_AUDIO'] = WHISPER_RETAIN_AUDIO
app.config['WHISPER_RETAIN_TRANSCRIBED_TEXT'] = WHISPER_RETAIN_TRANSCRIBED_TEXT
app.config['WHISPER_MODEL_SIZE'] = WHISPER_MODEL_SIZE
app.config['WHISPER_DEVICE'] = WHISPER_DEVICE
app.config['WHISPER_COMPUTE_TYPE'] = WHISPER_COMPUTE_TYPE

if app.config['DEBUG']:
    print(app.config)

# Run our assumptions check
assert check_configuration_assumptions(config=app.config)


# Allow us to get access to the end user's source IP
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)

# Initialize the database object
db = SQLAlchemy()

# turn off warnings to avoid a rather silly one being dropped in the terminal,
# see https://stackoverflow.com/a/20627316/13301284. 
pd.options.mode.chained_assignment = None

# Instantiate the Mailer object
mailer = Mailer(
    enabled = app.config['SMTP_ENABLED'],
    mail_server = app.config['SMTP_MAIL_SERVER'],
    port = app.config['SMTP_PORT'],
    username = app.config['SMTP_USERNAME'],
    password = app.config['SMTP_PASSWORD'],
    from_address = app.config['SMTP_FROM_ADDRESS'],
)

with app.app_context():
    signatures = Signatures(app, db=db, byte_len=32, 
        # Pass the rate limiting settings from the app config
        rate_limiting=app.config['RATE_LIMITS_ENABLED'], 
        rate_limiting_period=app.config['RATE_LIMITS_PERIOD'], 
        rate_limiting_max_requests=app.config['RATE_LIMITS_MAX_REQUESTS']
    )

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True) 
    email = db.Column(db.String(1000))
    password = db.Column(db.String(1000))
    username = db.Column(db.String(1000), unique=True)
    active = db.Column(db.Boolean)
    created_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True, default=datetime.utcnow)
    locked_until = db.Column(db.DateTime, nullable=True, default=datetime.utcnow)
    last_password_change = db.Column(db.DateTime, nullable=True, default=datetime.utcnow)
    failed_login_attempts = db.Column(db.Integer, default=0)
    # api_key_id = db.Column(db.Integer, db.ForeignKey('signing.id'), nullable=True)
    api_key = db.Column(db.String(1000), nullable=True, unique=True)
    # This opt out, if true, will exclude this user's ID and IP from the statistics
    # gathered from their usage, see https://github.com/signebedi/gita-api/issues/59.
    opt_out = db.Column(db.Boolean, nullable=False, default=True)
    site_admin = db.Column(db.Boolean, nullable=False, default=False)

    usage_log = db.relationship("UsageLog", order_by="UsageLog.id", back_populates="user")

    
# Many to one relationship with User table
class UsageLog(db.Model):
    __tablename__ = 'usage_log'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # date = db.Column(db.Date, nullable=False, default=lambda: datetime.utcnow().date())
    endpoint = db.Column(db.String(1000))
    remote_addr = db.Column(db.String(50), nullable=True)
    query_params = db.Column(db.String(1000), nullable=True)  # Can we find a way to make this a JSON string or similar format?

    user = db.relationship("User", back_populates="usage_log")

# We create the TranscribedText table in all cases, though its usage depends on 
# the WHISPER_RETAIN_TRANSCRIBED_TEXT configuration set in fw.
class TranscribedText(db.Model):
    __tablename__ = 'transcribed_text'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    text = db.Column(db.String, nullable=False)


db.init_app(app=app)
if app.config['DEBUG'] or app.config['TESTING']:
    with app.app_context():
        db.create_all()

# Arrange standard data to pass to jinja templates
def standard_view_kwargs():
    kwargs = {}
    kwargs['version'] = __version__
    kwargs['config'] = {
        "HCAPTCHA_ENABLED": app.config["HCAPTCHA_ENABLED"],
        "HCAPTCHA_SITE_KEY": app.config["HCAPTCHA_SITE_KEY"] if app.config["HCAPTCHA_ENABLED"] else None,
        'DISABLE_NEW_USERS': app.config['DISABLE_NEW_USERS'],
        "SITE_NAME": app.config['SITE_NAME'],
        "HOMEPAGE_CONTENT": app.config['HOMEPAGE_CONTENT'],
        "COLLECT_USAGE_STATISTICS": app.config["COLLECT_USAGE_STATISTICS"],
        "PRIVACY_MESSAGE": app.config["PRIVACY_MESSAGE"],
        "SITE_SOURCE_URL": app.config["SITE_SOURCE_URL"],
        "SMTP_ENABLED": app.config['SMTP_ENABLED'],
    }
    kwargs['current_user'] = current_user
    kwargs['current_year'] = datetime.now().year

    #  Here, we add a warning banner for admin users to let them know when a reload has been 
    # triggered and stability might be impacted.
    if os.path.exists(os.path.join(os.getcwd(), 'instance','.reload_triggered')) and current_user.is_authenticated and current_user.site_admin:
        kwargs['reload_warning_banner'] = True
    else:
        kwargs['reload_warning_banner'] = False

    # This determines whether the help_page_link will be displayed in the 
    # navbar, see https://github.com/signebedi/gita-api/issues/13.
    kwargs['show_help_page_link'] = True if app.config["HELP_PAGE_ENABLED"] and app.config['SMTP_ENABLED'] else False

    # This determines whether we show the navbar link to view the user's past
    # transcriptions, see https://github.com/signebedi/whisper-api/issues/11. 
    kwargs['show_transcriptions_history_link'] = True if app.config['WHISPER_RETAIN_TRANSCRIBED_TEXT'] else False

    return kwargs


# Create hCaptcha object if enabled
if app.config['HCAPTCHA_ENABLED']:
    from flask_hcaptcha import hCaptcha
    hcaptcha = hCaptcha()
    hcaptcha.init_app(app)

# Setup login manager
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

# Set flask session length. Session lifetime pulled
# from the PERMANENT_SESSION_LIFETIME config.
@app.before_request
def make_session_permanent():
    session.permanent = True

if app.config['CELERY_ENABLED']:

    celery = make_celery(app)

    @celery.task
    def send_email_async(subject=None, content=None, to_address=None, cc_address_list=[]):
        return mailer.send_mail(subject=subject, content=content, to_address=to_address, cc_address_list=cc_address_list)

    @celery.task
    def save_transcribed_text_to_db(api_key, text):
        user = User.query.filter_by(api_key=api_key).first()
        if user:
            transcribed_text = TranscribedText(
                    user_id=user.id,
                    text=text,
                )
            db.session.add(transcribed_text)

            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                # Placeholder for logging logic

        transcribed_text = TranscribedText(
                    user_id=current_user.id,
                    text=result['full_text']
                )
        db.session.add(transcribed_text)
        db.session.commit()



    @celery.task
    def log_api_call(api_key, endpoint, remote_addr=None, query_params={}):
        user = User.query.filter_by(api_key=api_key).first()
        if user:
            new_log = UsageLog(
                user_id=user.id if not user.opt_out else None,
                timestamp=datetime.utcnow(),
                endpoint=endpoint,
                query_params=json.dumps(query_params),
                remote_addr=remote_addr if not user.opt_out else None,
            )
            db.session.add(new_log)
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                # Placeholder for logging logic

    @celery.task()
    def check_key_rotation():

        # Query for signatures with scope 'api_key'
        keypairs = signatures.rotate_keys(time_until=1, scope="api_key")

        if len(keypairs) == 0:
            return
            
        # For each key that has just been rotated, update the user model with the new key
        for tup in keypairs:
            old_key, new_key = tup
            user = User.query.filter_by(api_key=old_key).first()

            if user:
                user.api_key = new_key
                db.session.commit()

                if app.config['SMTP_ENABLED']:

                    subject=f"{app.config['SITE_NAME']} API Key Rotated"
                    content=f"This email serves to notify you that an API key for user {username} has just rotated at {app.config['DOMAIN']}. Please note that your past API key will no longer work if you are employing it in applications. Your new key will be active for 365 days. You can see your new key by visiting {app.config['DOMAIN']}/profile."
                    email = user.email

                    send_email_async.delay(subject=subject, content=content, to_address=email)


    # If debug mode is set, we'll let the world pull API key usage statistics
    if app.config['DEBUG']:

        from sqlalchemy import create_engine

        @app.route('/stats', methods=['GET'])
        def stats():
           
            # Create an engine to your database
            engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])

            # SQL query or table name
            query = 'SELECT * FROM usage_log'

            # Read data into a pandas df
            stats_df = pd.read_sql(query, engine)
            
            # Convert DataFrame to a list of dictionaries
            data = stats_df.to_dict(orient='records')

            # print(data)
            # print(stats_df.to_json(orient='records'))

            json_str = stats_df.to_json(orient='records')

            return Response(json_str, mimetype='application/json'), 200


@app.route('/login', methods=['GET', 'POST'])
def login():

    # we only make this view visible if the user isn't logged in
    if current_user.is_authenticated:
        return redirect(url_for('home'))


    if request.method == 'POST':

        username = request.form.get('username', None)
        password = request.form.get('password', None)


        error = None

        if app.config["HCAPTCHA_ENABLED"]:
            if not hcaptcha.verify():
                flash('There was a Captcha validation error.', "warning")
                return redirect(url_for('login'))


        try:
            user = User.query.filter(User.username.ilike(username.lower())).first()
        except Exception as e:
            flash('There was a problem logging in. Please try again shortly. If the problem persists, contact your system administrator.', "warning")
            return redirect(url_for('login'))


        if not user:
            error = 'Incorrect username. '
        elif not check_password_hash(user.password, password):

            if app.config["MAX_LOGIN_ATTEMPTS"]:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= app.config["MAX_LOGIN_ATTEMPTS"]:
                    # user.active = False
                    user.locked_until = datetime.utcnow() + timedelta(hours=1)

                    # Calculate the time difference
                    time_diff = user.locked_until - datetime.utcnow()

                    # Extract hours and minutes
                    hours, remainder = divmod(time_diff.seconds, 3600)
                    minutes = remainder // 60

                    # Create a string representing the time delta in hours and minutes
                    time_delta_str = f"{hours} hours, {minutes} minutes" if hours else f"{minutes} minutes"

                    flash(f'Account is locked due to too many failed login attempts. Please try again in {time_delta_str}.', 'danger') 
                db.session.commit()
            error = 'Incorrect password. '

        elif not user.active:
            flash('Your user is currently inactive. If you recently registered, please check your email for a verification link. If you believe this may be a mistake, please contact your system administrator.', "warning")
            return redirect(url_for('login'))


        elif user.locked_until > datetime.utcnow():

            # Calculate the time difference
            time_diff = user.locked_until - datetime.utcnow()

            # Extract hours and minutes
            hours, remainder = divmod(time_diff.seconds, 3600)
            minutes = remainder // 60

            # Create a string representing the time delta in hours and minutes
            time_delta_str = f"{hours} hours, {minutes} minutes" if hours else f"{minutes} minutes"

            flash(f'User is locked. Please try again in {time_delta_str}.', 'danger')
            return redirect(url_for('login'))

        if error is None:

            login_user(user, remember=False)

            # Update last_login time and reset the failed login attempts
            user.last_login = datetime.now()
            user.failed_login_attempts = 0
            db.session.commit()

            flash(f'Successfully logged in user \'{username.lower()}\'.', "success")

            return redirect(url_for('home'))

        flash(error, "warning")


    return render_template('login.html.jinja', 
                            **standard_view_kwargs()
                            )

@app.route('/rotate', methods=['GET'])
@login_required
def rotate():

    old_key = current_user.api_key

    # Rotate the current user's API key 
    new_key = signatures.rotate_key(old_key)

    user = User.query.filter_by(api_key=old_key).first()

    if user:
        user.api_key = new_key
        db.session.commit()

    flash("You have generated a new API key.", "success")
    return redirect(url_for('profile'))



@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash("You have successfully logged out.", "success")
    return redirect(url_for('home'))

@app.route('/profile')
@login_required
def profile():

       
    # Let's get the expiry of the current user's key
    s = current_user.api_key
    get_key = signatures.get_key(s)
    key_expiry=get_key['expiration']

    return render_template('profile.html.jinja', 
                            key_expiry=key_expiry,
                            **standard_view_kwargs()
                            )


@app.route('/create', methods=['GET', 'POST'])
def create_user():

    if app.config['DISABLE_NEW_USERS']:
        return abort(404)

    # we only make this view visible if the user isn't logged in
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        # print(request.form)
        username = request.form.get('username', None)
        password = request.form.get('password', None)
        email = request.form.get('email', None)
        opt_out = 'optOut' in request.form


        # Placeholder for https://github.com/signebedi/gita-api/issues/15
        # reenter_password = request.form.get['reenter_password']

        if app.config["HCAPTCHA_ENABLED"]:
            if not hcaptcha.verify():
                flash('There was a Captcha validation error.', "warning")
                return redirect(url_for('login'))

        if username == "":
            username = None
        if email == "":
            email = None

        error = None

        if not username:
            error = 'Username is required. '
        elif not password:
            error = 'Password is required. '
        elif not email:
            error = 'Email is required. '

        elif email and User.query.filter(User.email.ilike(email)).first():
            error = 'Email is already registered. ' 
        elif User.query.filter(User.username.ilike(username.lower())).first():
            error = f'Username {username.lower()} is already registered. ' 

        if error is None:
            try:
                new_user = User(
                            email=email, 
                            username=username.lower(), 
                            password=generate_password_hash(password),
                            active=app.config["REQUIRE_EMAIL_VERIFICATION"] == False,
                            opt_out=opt_out if app.config["COLLECT_USAGE_STATISTICS"] else True,
                        ) 
                # print(new_user.opt_out)

                # Create the users API key. If Celery disabled, never expire keys 
                expiration = 365*24 if app.config['CELERY_ENABLED'] else 0
                api_key = signatures.write_key(scope=['api_key'], expiration=expiration, active=True, email=email)
                new_user.api_key = api_key

                db.session.add(new_user)
                db.session.commit()

                # Email notification
                subject=f"{app.config['SITE_NAME']} User Registered"

                if app.config["REQUIRE_EMAIL_VERIFICATION"]:

                    key = signatures.write_key(scope=['email_verification'], expiration=48, active=True, email=email)
                    content=f"This email serves to notify you that the user {username} has just been registered for this email address at {app.config['DOMAIN']}. Please verify your email by clicking the following link: {app.config['DOMAIN']}/verify/{key}. Please note this link will expire after 48 hours."
                    flash_msg = f'Successfully created user \'{username}\'. Please check your email for an activation link.'

                else:
                    content=f"This email serves to notify you that the user {username} has just been registered for this email address at {app.config['DOMAIN']}."
                    flash_msg = f'Successfully created user \'{username}\'.'
            
                # Send email, asynchronously only if celery is enabled
                if app.config['SMTP_ENABLED']:
                    if app.config['CELERY_ENABLED']:
                        send_email_async.delay(subject=subject, content=content, to_address=email)
                    else:
                        mailer.send_mail(subject=subject, content=content, to_address=email)

                flash(flash_msg, "success")

            except Exception as e: 
                error = f"There was an issue registering the user.{' '+str(e) if env != 'production' else ''}"
            else:
                return redirect(url_for('login'))

        flash(f"There was an error in processing your request. {error}", 'warning')

    return render_template('create_user.html.jinja', 
                            **standard_view_kwargs()
                            )


@app.route('/help', methods=['GET', 'POST'])
@login_required
def help():

    if not app.config["HELP_PAGE_ENABLED"] or not app.config['SMTP_ENABLED']:
        return abort(404)

    if request.method == 'POST':
                
        subject = request.form.get('subject', None)
        category = request.form.get('category', None)
        message = request.form.get('message', None)

        # print(subject, category, message)

        # Return if no subject is provided, else strip and escape it
        if not subject:
            flash('No subject provided.', 'warning')
            return redirect(url_for('help'))
        subject = escape(subject).strip()

        # Return if no message is provided, else escape it
        if not message:
            flash('No message provided.', 'warning')
            return redirect(url_for('help'))
        message = escape(message)

        # print(subject, category, message)

        # We combine a number of values to make the email subject more detailed, following
        # the format: [SITENAME][USERNAME][CATEGORY] User Provided Subject 
        full_subject = f"[{app.config['SITE_NAME']}][{current_user.username}][{category}] {subject}"

        # print(full_subject)

        # Send email, asynchronously only if celery is enabled
        if app.config['SMTP_ENABLED']:
            if app.config['CELERY_ENABLED']:
                send_email_async.delay(subject=full_subject, content=message, to_address=app.config["HELP_EMAIL"], cc_address_list=[current_user.email])
            else:
                mailer.send_mail(subject=full_subject, content=message, to_address=app.config["HELP_EMAIL"], cc_address_list=[current_user.email])

        flash("Help Request successfully submitted", "success")
        return redirect(url_for('help'))

    return render_template('help.html.jinja', 
                            **standard_view_kwargs()
                            )

@app.route('/verify/<signature>', methods=('GET', 'POST'))
def verify_email(signature):

    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if not app.config["REQUIRE_EMAIL_VERIFICATION"]:
        return abort(404)

    valid = signatures.verify_key(signature=signature, scope='email_verification')

    if valid:

        s = signatures.get_model().query.filter_by(signature=signature).first()
        email = s.email

        try:
            user = User.query.filter_by(email=str(email)).first() 
            user.active = True
            db.session.commit()

            signatures.expire_key(signature)
            flash(f"Successfully activated user {user.username}.", "success")
            return redirect(url_for('login'))

        except Exception as e: 
            flash (f"There was an error in processing your request.{' '+str(e) if env != 'production' else ''}", 'warning')
    
    return redirect(url_for('login'))


@app.route('/admin/reload', methods=['GET'])
@login_required
def admin_trigger_reload():
    if not current_user.site_admin:
        return abort(404)

    try:
        # Touch the .reload_triggered file
        reload_file = os.path.join('instance', '.reload_triggered')          
        with open(reload_file, 'a'):
            os.utime(reload_file, None)
        flash (f"Reload successfully scheduled.", 'success')
        return redirect(url_for('home'))
    except Exception as e:

        flash (f"Error reloading application: {e}", 'warning')
        return redirect(url_for('home'))

@app.route('/admin/stats', methods=['GET'])
@login_required
def admin_stats():

    if not current_user.site_admin:
        return abort(404)

    if not app.config["COLLECT_USAGE_STATISTICS"]:
        flash("User statistics not enabled on this server.", 'warning')
        return redirect(url_for('home'))

    from sqlalchemy import create_engine

    # Create an engine to your database
    engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])

    # SQL query
    query = 'SELECT * FROM usage_log'
    stats_df = pd.read_sql(query, engine)

    # Aggregate data by day for endpoint after casting timestamp as a datetime object
    stats_df['timestamp'] = pd.to_datetime(stats_df['timestamp'])
    stats_df['date'] = stats_df['timestamp'].dt.date
    daily_stats = stats_df.groupby(['date', 'endpoint']).size().reset_index(name='count')

    # print(daily_stats)

    # Convert to json .... ?
    # daily_stats_json = daily_stats.to_json(orient='records')

    # Basic figure
    fig = px.bar(daily_stats, x='date', y='count', color='endpoint',title='Day-over-day activity by endpoint')

    # Format the x-axis to display dates only
    fig.update_xaxes(
        tickformat='%Y-%m-%d',
        tickangle=-45,
        tickvals=daily_stats['date'].unique(),
    )

    # Set the default range for the x-axis to the last 5 days
    # today = datetime.now().date()
    # end_date = today + timedelta(days=1)
    # start_date = end_date - timedelta(days=5)
    # fig.update_xaxes(range=[start_date, end_date])

    # Set a gap between days
    # fig.update_layout(bargap=.85)

    # Convert the figure to JSON
    graph_json = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template('admin_stats.html.jinja',
                            graph_json=graph_json,
                            **standard_view_kwargs()
                            )



@app.route('/admin/users', methods=['GET'])
@login_required
def admin_users():

    if not current_user.site_admin:
        return abort(404)

    users = User.query.all()

    return render_template('admin_users.html.jinja',
                            users=users,
                            **standard_view_kwargs()
                            )


@app.route('/admin/toggle/<username>', methods=['GET'])
@login_required
def admin_toggle_user_active_status(username):

    if not current_user.site_admin:
        return abort(404)

    user = User.query.filter_by(username=username.lower()).first()

    if not user:
        flash (f'User {username} does not exist.', 'warning')
        return redirect(url_for('admin_users'))

    if current_user.id == user.id:
        flash (f'You cannot deactivate the user you are currently logged in as.', 'warning')
        return redirect(url_for('admin_users'))

    if user.active == 0:
        user.active = 1 
        # Update user last login date when user is set to active to ensure
        # user is not immediately deactivated when they try to login.
        user.last_login = datetime.now() 
        db.session.commit()
        flash (f'Activated user {username}. ', 'info')

    else:
        user.active = 0
        db.session.commit()
        flash (f'Deactivated user {username}. ', 'info')

    return redirect(url_for('admin_users'))


@app.route('/admin/config/site', methods=['GET', 'POST'])
@login_required
def admin_config_site():

    if not current_user.site_admin:
        return abort(404)

    if request.method == 'POST':

        # Create a dictionary to hold the form inputs
        kwargs = {
            'SITE_NAME': request.form.get('SITE_NAME'),
            'DOMAIN': request.form.get('DOMAIN'),
            'HOMEPAGE_CONTENT': request.form.get('HOMEPAGE_CONTENT'),
            'PRIVACY_MESSAGE': request.form.get('PRIVACY_MESSAGE'),
            'RATE_LIMITS_PERIOD': int(float(request.form.get('RATE_LIMITS_PERIOD', 0))),
            'RATE_LIMITS_MAX_REQUESTS': request.form.get('RATE_LIMITS_MAX_REQUESTS'),
            'MAX_LOGIN_ATTEMPTS': request.form.get('MAX_LOGIN_ATTEMPTS'),
            'PERMANENT_SESSION_LIFETIME': int(float(request.form.get('PERMANENT_SESSION_LIFETIME', 0))),
            'RATE_LIMITS_ENABLED': 'RATE_LIMITS_ENABLED' in request.form,
            'REQUIRE_EMAIL_VERIFICATION': 'REQUIRE_EMAIL_VERIFICATION' in request.form,
            'COLLECT_USAGE_STATISTICS': 'COLLECT_USAGE_STATISTICS' in request.form,
            'DISABLE_NEW_USERS': 'DISABLE_NEW_USERS' in request.form,
        }

        validate_and_write_configs(app.config, **kwargs)

        flash('Configs successfully updated. App reload needed for changes to take effect.','success')
        return redirect(url_for("admin_config_site"))

    return render_template('admin_config_site.html.jinja',
                            app_config=app.config,
                            **standard_view_kwargs()
                            )

@app.route('/admin/config/smtp', methods=['GET', 'POST'])
@login_required
def admin_config_smtp():

    if not current_user.site_admin:
        return abort(404)

    if request.method == 'POST':

        # Create a dictionary to hold the form inputs
        kwargs = {
        'SMTP_ENABLED': 'SMTP_ENABLED' in request.form,
        'SMTP_MAIL_SERVER': request.form.get('SMTP_MAIL_SERVER'),
        'SMTP_PORT': int(request.form.get('SMTP_PORT', 25)),
        'SMTP_USERNAME': request.form.get('SMTP_USERNAME'),
        'SMTP_FROM_ADDRESS': request.form.get('SMTP_FROM_ADDRESS')
        }

        # Only add SMTP_PASSWORD to kwargs if it's provided (not empty)
        smtp_password = request.form.get('SMTP_PASSWORD', None)
        if smtp_password and smtp_password != "":
            kwargs['SMTP_PASSWORD'] = smtp_password


        validate_and_write_configs(app.config, **kwargs)

        flash('Configs successfully updated. App reload needed for changes to take effect.','success')
        return redirect(url_for("admin_config_smtp"))

    return render_template('admin_config_smtp.html.jinja',
                            app_config=app.config,
                            **standard_view_kwargs()
                            )


@app.route('/admin/config/celery', methods=['GET', 'POST'])
@login_required
def admin_config_celery():

    if not current_user.site_admin:
        return abort(404)

    if request.method == 'POST':

        # Create a dictionary to hold the form inputs
        kwargs = {
            'CELERY_ENABLED': 'CELERY_ENABLED' in request.form,
            'CELERY_BROKER_URL': request.form.get('CELERY_BROKER_URL'),
            'CELERY_RESULT_BACKEND': request.form.get('CELERY_RESULT_BACKEND'),
        }

        validate_and_write_configs(app.config, **kwargs)

        flash('Configs successfully updated. App reload needed for changes to take effect.','success')
        return redirect(url_for("admin_config_celery"))


    return render_template('admin_config_celery.html.jinja',
                            app_config=app.config,
                            **standard_view_kwargs()
                            )


@app.route('/admin/config/hcaptcha', methods=['GET', 'POST'])
@login_required
def admin_config_hcaptcha():

    if not current_user.site_admin:
        return abort(404)

    if request.method == 'POST':

        # Create a dictionary to hold the form inputs
        kwargs = {
            'HCAPTCHA_ENABLED': 'HCAPTCHA_ENABLED' in request.form,
            'HCAPTCHA_SITE_KEY': request.form.get('HCAPTCHA_SITE_KEY'),
        }

        # Only add HCAPTCHA_SECRET_KEY to kwargs if it's provided (not empty)
        hcaptcha_secret_key = request.form.get('HCAPTCHA_SECRET_KEY', None)
        if hcaptcha_secret_key and hcaptcha_secret_key != "":
            kwargs['HCAPTCHA_SECRET_KEY'] = hcaptcha_secret_key

        validate_and_write_configs(app.config, **kwargs)

        flash('Configs successfully updated. App reload needed for changes to take effect.','success')
        return redirect(url_for("admin_config_hcaptcha"))


    return render_template('admin_config_hcaptcha.html.jinja',
                            app_config=app.config,
                            **standard_view_kwargs()
                            )


@app.route('/admin/config/database', methods=['GET', 'POST'])
@login_required
def admin_config_database():

    if not current_user.site_admin:
        return abort(404)

    if request.method == 'POST':

        # Create a dictionary to hold the form inputs
        kwargs = {
            'SQLALCHEMY_DATABASE_URI': request.form.get('SQLALCHEMY_DATABASE_URI'),
        }

        validate_and_write_configs(app.config, **kwargs)

        flash('Configs successfully updated. App reload needed for changes to take effect.','success')
        return redirect(url_for("admin_config_database"))


    return render_template('admin_config_database.html.jinja',
                            app_config=app.config,
                            **standard_view_kwargs()
                            )



@app.route('/', methods=['GET'])
def home():
    return render_template('about.html.jinja', **standard_view_kwargs())



@app.route('/privacy', methods=['GET'])
def privacy():
    return render_template('privacy.html.jinja', **standard_view_kwargs())

##################################################
### App-Specific Views
##################################################

@app.route('/record', methods=['GET'])
@login_required
def record():
    return render_template('record.html.jinja', 
                            **standard_view_kwargs()
                            )



@app.route('/upload', methods=['GET'])
@login_required
def upload():
    return render_template('upload.html.jinja', 
                            **standard_view_kwargs()
                            )

@app.route('/history', methods=['GET'])
@login_required
def history():

    if not app.config['WHISPER_RETAIN_TRANSCRIBED_TEXT']:
        return abort(404)

    transcriptions = TranscribedText.query.filter_by(user_id=current_user.id).all()
    # transcriptions = TranscribedText.query.filter_by(user_id=current_user.id).order_by(
    #     desc(TranscribedText.timestamp)
    # ).all()


    return render_template('history.html.jinja', 
                            transcriptions=transcriptions,
                            **standard_view_kwargs()
                            )

@app.route('/api/send_mail', methods=['POST'])
def api_email_result():

    if not app.config["SMTP_ENABLED"]:
        return abort(404)

    signature = request.headers.get('X-API-KEY', None)
    if not signature:
        return jsonify({'error': 'No API key provided'}), 401

    try:
        valid = signatures.verify_key(signature, scope=["api_key"]) # if not app.config['TESTING'] else True

    except RateLimitExceeded:
        return jsonify({'error': 'Rate limit exceeded'}), 429

    except KeyDoesNotExist:
        return jsonify({'error': 'Invalid API key'}), 401

    except KeyExpired:
        return jsonify({'error': 'API key expired'}), 401

    user = User.query.filter_by(api_key=signature).first()
    if not user:
        return jsonify({'error': 'No valid user account registered for this API key'}), 401

    text = request.json['text']
    if not text:
        return jsonify({"error": "No text was provided"}), 400

    timestamp = datetime.utcnow()
    subject = f"{app.config['SITE_NAME']} transcribed data {timestamp}"

    # Send email, asynchronously only if celery is enabled
    if app.config['SMTP_ENABLED']:
        if app.config['CELERY_ENABLED']:
            send_email_async.delay(subject=subject, content=text, to_address=user.email)
        else:
            mailer.send_mail(subject=subject, content=text, to_address=user.email)
    
    return jsonify({'result': "sucess"}), 200


@app.route('/api/transcribe', methods=['POST'])
def api_transcript():

    signature = request.headers.get('X-API-KEY', None)
    if not signature:
        return jsonify({'error': 'No API key provided'}), 401

    try:
        valid = signatures.verify_key(signature, scope=["api_key"]) # if not app.config['TESTING'] else True

    except RateLimitExceeded:
        return jsonify({'error': 'Rate limit exceeded'}), 429

    except KeyDoesNotExist:
        return jsonify({'error': 'Invalid API key'}), 401

    except KeyExpired:
        return jsonify({'error': 'API key expired'}), 401

    if 'audio' not in request.files:
        return jsonify({"error": "No audio file was uploaded"}), 400
    
    # Get the audio file
    audio_file = request.files['audio']
    
    # Decide whether to save permanently or as a temp file
    if app.config['WHISPER_RETAIN_AUDIO']:
        # Ensure the static/audio directory exists
        save_dir = os.path.join(os.getcwd(), 'instance', "audio") 
        os.makedirs(save_dir, exist_ok=True)
        
        # Save to the static/audio directory
        filepath = os.path.join(save_dir, f"{datetime.now().strftime('%Y%m%d%H%M%S')}.mp3")
        audio_file.save(filepath)

        # Process the saved file
        result = transcribe_audio(filepath)

    else:
        # Use a temporary file that is automatically removed
        with tempfile.NamedTemporaryFile(delete=True) as temp_file:
            audio_file.save(temp_file.name)
            filepath = temp_file.name
            # Process the audio file here
            try:
                result = transcribe_audio(filepath)

            except Exception as e:
                return jsonify({"error": str(e)}), 500

    if app.config['COLLECT_USAGE_STATISTICS']:

        router = request.url_rule
        route_path = route.rule

        # Call our Celery task
        log_api_call.delay(signature, route_path, remote_addr=request.remote_addr)


        if app.config['WHISPER_RETAIN_TRANSCRIBED_TEXT']:
            save_transcribed_text_to_db.delay(signature, text=result['full_text'])
    else:
        # Run synchronously if celery is not enabled...
        if app.config['WHISPER_RETAIN_TRANSCRIBED_TEXT']:

            user = User.query.filter_by(api_key=signature).first()
            if user:
                transcribed_text = TranscribedText(
                        user_id=user.id,
                        text=result['full_text']
                    )
                db.session.add(transcribed_text)

                try:
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()

    return jsonify({'content': result}), 200


if __name__ == '__main__':
    app.run(debug=True)
