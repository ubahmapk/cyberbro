from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class AnalysisResult(db.Model):
    id = db.Column(db.String, primary_key=True)
    results = db.Column(db.JSON, nullable=False)
    start_time = db.Column(db.Float, nullable=False)
    end_time = db.Column(db.Float, nullable=False)
    start_time_string = db.Column(db.String, nullable=False)
    end_time_string = db.Column(db.String, nullable=False)
    analysis_duration_string = db.Column(db.String, nullable=False)
    analysis_duration = db.Column(db.Float, nullable=False)
    selected_engines = db.Column(db.JSON, nullable=False)