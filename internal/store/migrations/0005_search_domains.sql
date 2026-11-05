-- A device may list several DNS search domains, kept in order like its
-- resolvers. Existing single search domains become the first entry.
CREATE TABLE device_search_domains (
    device_id TEXT NOT NULL REFERENCES devices(id),
    position INTEGER NOT NULL CHECK (position >= 0),
    domain TEXT NOT NULL,
    PRIMARY KEY (device_id, position),
    UNIQUE (device_id, domain)
);

INSERT INTO device_search_domains (device_id, position, domain)
SELECT id, 0, search_domain FROM devices WHERE search_domain IS NOT NULL AND search_domain != '';

ALTER TABLE devices DROP COLUMN search_domain;
