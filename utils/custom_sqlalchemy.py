from flask_sqlalchemy import SQLAlchemy as _BaseSQLAlchemy

# From: https://stackoverflow.com/q/55457069/13301284
class SQLAlchemy(_BaseSQLAlchemy):
    def apply_pool_defaults(self, app, options):
        super(SQLAlchemy, self).apply_pool_defaults(self, app, options)
        options["pool_pre_ping"] = True