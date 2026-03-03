from flask import Blueprint, render_template, redirect, url_for

bp = Blueprint("main", __name__)

@bp.get("/")
def index():
    return redirect(url_for("scans.dashboard"))
