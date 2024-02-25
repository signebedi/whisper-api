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

import re, os, json
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
from faster_whisper import WhisperModel

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



def some_func():

        model_size = "medium"

        # Run on GPU with FP16
        model = WhisperModel(model_size, device="cpu", compute_type="int8")

        # or run on GPU with INT8
        # model = WhisperModel(model_size, device="cuda", compute_type="int8_float16")
        # or run on CPU with INT8
        # model = WhisperModel(model_size, device="cpu", compute_type="int8")

        segments, info = model.transcribe("OSR_us_000_0012_8k.wav", language="en", beam_size=5, word_timestamps=True)

        # print("Detected language '%s' with probability %f" % (info.language, info.language_probability))

        # for segment in segments:
        #     print("[%.2fs -> %.2fs] %s" % (segment.start, segment.end, segment.text))

        text = " ".join([f"[{s.start}] {s.text}" for s in segments])



@app.route('/api/<corpus_name>/fuzzy', methods=['GET'])
def fuzzy_search(corpus_name):

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

    # Return an error if not a valid corpus
    if corpus_name not in corpora_shorthands:
        return jsonify({'error': 'Invalid Corpus Name'}), 400

    author_id = int(request.args.get('author_id', default='16'))

    # Return an error if not a valid author
    if not any(tuple_[0] == author_id for tuple_ in just_authors_by_corpus[corpus_name]):
        return jsonify({'error': 'Invalid Author ID'}), 400

    search_query = request.args.get('query')

    if not search_query:
        return jsonify({'error': 'No search query provided'}), 400

    search_query = escape(search_query.strip())
    
    # Limit length of the search string
    if len(search_query) > 100:
        return jsonify({'error': 'Query too long. Please keep length at or below 100 chars.'}), 400

    # Call the fuzzy search function

    try:

        search_results = perform_fuzzy_search(search_query, df=datasets[corpus_name]['text'], author_id=author_id)

        if app.config['COLLECT_USAGE_STATISTICS']:
            # Call our Celery task
            log_api_call.delay(signature, '/fuzzy', remote_addr=request.remote_addr, query_params={"query": search_query, "author_id": author_id})

    except ValueError as e:
        return jsonify({'error': str(e)}), 400


    return jsonify({'content': search_results}), 200
