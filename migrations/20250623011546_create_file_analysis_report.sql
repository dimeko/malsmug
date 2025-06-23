CREATE TABLE file_analysis_reports (
    uid TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    file_name TEXT NOT NULL,
    analysis_report_description TEXT NOT NULL
);