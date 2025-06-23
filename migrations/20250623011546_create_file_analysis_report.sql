CREATE TABLE file_analysis_reports (
    uid VARCHAR NOT NULL PRIMARY KEY,
    name TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    file_name TEXT NOT NULL,
    has_been_analysed BOOLEAN DEFAULT false NOT NULL,
    severity INTEGER NOT NULL,
    analysis_report_description TEXT NOT NULL
);