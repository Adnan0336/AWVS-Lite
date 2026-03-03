import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def create_app():
    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static"
    )

    app.config["SECRET_KEY"] = os.getenv("AWVS_SECRET_KEY", "change-me")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("AWVS_DB_URI", "sqlite:///awvs_lite.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)

    from app.blueprints.main import bp as main_bp
    from app.blueprints.scans import bp as scans_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(scans_bp, url_prefix="/scans")

    with app.app_context():
        from app import models  # noqa
        db.create_all()

    return app
