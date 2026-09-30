-- NS-054: nullable additions preserve the meaning of all pre-010 rows.
ALTER TABLE connection_history ADD COLUMN executable_path TEXT
    CHECK (executable_path IS NULL OR (length(executable_path) BETWEEN 1 AND 4096
        AND length(trim(executable_path)) > 0));
ALTER TABLE connection_history ADD COLUMN process_name_status TEXT
    CHECK (process_name_status IS NULL OR process_name_status IN
        ('available', 'access_denied', 'not_found', 'unavailable'));
ALTER TABLE connection_history ADD COLUMN process_create_time_status TEXT
    CHECK (process_create_time_status IS NULL OR process_create_time_status IN
        ('available', 'access_denied', 'not_found', 'unavailable'));
ALTER TABLE connection_history ADD COLUMN executable_path_status TEXT
    CHECK (executable_path_status IS NULL OR executable_path_status IN
        ('available', 'access_denied', 'not_found', 'unavailable'));
ALTER TABLE connection_history ADD COLUMN parent_status TEXT
    CHECK (parent_status IS NULL OR parent_status IN
        ('observed', 'absent', 'access_denied', 'not_found', 'reused', 'unavailable'));
ALTER TABLE connection_history ADD COLUMN parent_observed_at_utc_us INTEGER
    CHECK (parent_observed_at_utc_us IS NULL OR parent_observed_at_utc_us >= 0);
ALTER TABLE connection_history ADD COLUMN parent_pid INTEGER
    CHECK (parent_pid IS NULL OR parent_pid > 0);
ALTER TABLE connection_history ADD COLUMN parent_create_time_utc_us INTEGER
    CHECK (parent_create_time_utc_us IS NULL OR parent_create_time_utc_us >= 0);
ALTER TABLE connection_history ADD COLUMN parent_name TEXT
    CHECK (parent_name IS NULL OR (length(parent_name) BETWEEN 1 AND 255
        AND length(trim(parent_name)) > 0));
ALTER TABLE connection_history ADD COLUMN parent_pid_status TEXT
    CHECK (parent_pid_status IS NULL OR parent_pid_status IN
        ('available', 'access_denied', 'not_found', 'unavailable'));
ALTER TABLE connection_history ADD COLUMN parent_create_time_status TEXT
    CHECK (parent_create_time_status IS NULL OR parent_create_time_status IN
        ('available', 'access_denied', 'not_found', 'unavailable'));
ALTER TABLE connection_history ADD COLUMN parent_name_status TEXT
    CHECK (parent_name_status IS NULL OR parent_name_status IN
        ('available', 'access_denied', 'not_found', 'unavailable'));
