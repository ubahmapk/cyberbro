from models.analysis_result import AnalysisResult, db

def save_analysis_result_to_db(analysis_id, analysis_metadata_dict, results_dict):
    """Save the analysis result to the database."""
    analysis_result = create_analysis_result(analysis_id, analysis_metadata_dict, results_dict)
    db.session.add(analysis_result)
    db.session.commit()

def create_analysis_result(analysis_id, analysis_metadata_dict, results_dict):
    """Create an AnalysisResult object from the analysis data."""
    return AnalysisResult(
        id=analysis_id,
        results=results_dict.get(analysis_id, []),
        start_time=analysis_metadata_dict[analysis_id]["start_time"],
        end_time=analysis_metadata_dict[analysis_id]["end_time"],
        start_time_string=analysis_metadata_dict[analysis_id]["start_time_string"],
        end_time_string=analysis_metadata_dict[analysis_id]["end_time_string"],
        analysis_duration_string=analysis_metadata_dict[analysis_id]["analysis_duration_string"],
        analysis_duration=analysis_metadata_dict[analysis_id]["analysis_duration"],
        selected_engines=analysis_metadata_dict[analysis_id]["selected_engines"]
    )