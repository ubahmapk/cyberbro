from models.analysis_result import AnalysisResult, db

def save_analysis_result(analysis_result):
    """Save the analysis result to the database."""
    db.session.add(analysis_result)
    db.session.commit()

def get_analysis_result(analysis_id):
    """Get the analysis result from the database."""
    return db.session.query(AnalysisResult).filter_by(id=analysis_id).first()