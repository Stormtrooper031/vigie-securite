-- =====================================================================
--  Vigie Sécurité - Schéma PostgreSQL
--  Exécuté automatiquement au premier démarrage du conteneur PostgreSQL
--  (dossier /docker-entrypoint-initdb.d, connecté en POSTGRES_USER sur
--  POSTGRES_DB). Pour le rejouer : supprimer le volume "vigie_pg_data"
--  (docker compose down -v).
--  Toutes les dates sont en timestamptz (stockage UTC).
-- =====================================================================

SET client_encoding = 'UTF8';

-- Mise à jour automatique de updated_at
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------
-- technologies : ma stack à surveiller
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS technologies (
    id               integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name             varchar(200)  NOT NULL,                  -- nom affiché (ex. "ASP.NET Core")
    type             varchar(30)   NOT NULL DEFAULT 'other',  -- os|framework|library|runtime|database|webserver|docker_image|application|other
    vendor           varchar(150)  NOT NULL DEFAULT '',       -- vendeur CPE normalisé (ex. microsoft)
    product          varchar(150)  NOT NULL,                  -- produit CPE normalisé (ex. asp.net_core)
    version          varchar(100)  NOT NULL DEFAULT '',       -- version installée (vide = toutes)
    ecosystem        varchar(50)   NOT NULL DEFAULT '',       -- écosystème OSV : npm|NuGet|PyPI|Packagist|Maven|Go|Debian|Alpine|Ubuntu...
    package_name     varchar(200)  NULL,                      -- nom exact du paquet dans l'écosystème
    cpe              varchar(300)  NULL,                      -- CPE 2.3 (généré si absent)
    keywords         varchar(500)  NULL,                      -- mots-clés supplémentaires (virgules)
    source_line      varchar(500)  NULL,                      -- ligne d'origine fournie par l'utilisateur
    is_active        boolean       NOT NULL DEFAULT true,
    notes            text          NULL,
    solutions        text[]        NOT NULL DEFAULT '{}',     -- solutions (applications) qui utilisent la technologie, ex. {PAC+}
    last_scanned_at  timestamptz   NULL,                      -- NULL = jamais scanné (inventaire complet au prochain scan)
    created_at       timestamptz   NOT NULL DEFAULT now(),
    updated_at       timestamptz   NOT NULL DEFAULT now(),
    CONSTRAINT uq_technology UNIQUE (type, vendor, product, version, ecosystem)
);
CREATE INDEX IF NOT EXISTS ix_technology_active ON technologies (is_active);
CREATE OR REPLACE TRIGGER trg_technologies_updated BEFORE UPDATE ON technologies
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------
-- vulnerabilities : failles normalisées (NVD, OSV, MITRE) + KEV + EPSS
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id                   integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    external_id          varchar(80)   NOT NULL,              -- CVE-2024-1234 ou GHSA-xxxx (si aucun CVE)
    cve_id               varchar(30)   NULL,
    aliases              text          NULL,                  -- JSON ["GHSA-...", "DSA-..."]
    title                varchar(500)  NULL,
    description          text          NULL,
    cvss_score           numeric(3,1)  NULL,
    cvss_vector          varchar(200)  NULL,
    cvss_version         varchar(10)   NULL,
    severity             varchar(10)   NOT NULL DEFAULT 'UNKNOWN', -- CRITICAL|HIGH|MEDIUM|LOW|NONE|UNKNOWN (sévérité CVSS brute)
    epss_score           numeric(6,5)  NULL,                  -- probabilité d'exploitation 30 j (FIRST.org)
    epss_percentile      numeric(6,5)  NULL,
    in_kev               boolean       NOT NULL DEFAULT false, -- présent dans le catalogue CISA KEV
    kev_date_added       date          NULL,
    kev_due_date         date          NULL,
    kev_ransomware       varchar(20)   NULL,
    kev_required_action  text          NULL,
    cwe                  varchar(200)  NULL,
    source               varchar(20)   NOT NULL,              -- NVD|OSV|MITRE
    source_status        varchar(50)   NULL,                  -- statut NVD (Analyzed, Awaiting Analysis...)
    affected             text          NULL,                  -- JSON normalisé des produits/versions affectés
    fixed_versions       varchar(500)  NULL,                  -- versions corrigées connues (texte)
    references_json      text          NULL,                  -- JSON [{url, tags}]
    published_at         timestamptz   NULL,
    last_modified_at     timestamptz   NULL,
    created_at           timestamptz   NOT NULL DEFAULT now(),
    updated_at           timestamptz   NOT NULL DEFAULT now(),
    CONSTRAINT uq_vuln_external UNIQUE (external_id)
);
CREATE INDEX IF NOT EXISTS ix_vuln_cve       ON vulnerabilities (cve_id);
CREATE INDEX IF NOT EXISTS ix_vuln_severity  ON vulnerabilities (severity);
CREATE INDEX IF NOT EXISTS ix_vuln_published ON vulnerabilities (published_at);
CREATE INDEX IF NOT EXISTS ix_vuln_kev       ON vulnerabilities (in_kev);
CREATE OR REPLACE TRIGGER trg_vulnerabilities_updated BEFORE UPDATE ON vulnerabilities
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------
-- vulnerability_technology : corrélation faille <-> technologie
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS vulnerability_technology (
    vulnerability_id  integer      NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    technology_id     integer      NOT NULL REFERENCES technologies(id)    ON DELETE CASCADE,
    match_source      varchar(20)  NOT NULL,                  -- NVD_CPE|OSV|MITRE|KEV|KEYWORD
    confidence        varchar(20)  NOT NULL DEFAULT 'confirmed', -- confirmed (version dans la plage) | probable
    matched_rule      varchar(500) NULL,                      -- règle qui a matché (lisible)
    fixed_version     varchar(100) NULL,                      -- version corrigée pour CETTE technologie (mise à jour à faire)
    is_baseline       boolean      NOT NULL DEFAULT false,    -- true = trouvée lors de l'inventaire initial
    first_seen_at     timestamptz  NOT NULL DEFAULT now(),
    PRIMARY KEY (vulnerability_id, technology_id)
);
CREATE INDEX IF NOT EXISTS ix_vt_technology ON vulnerability_technology (technology_id);
CREATE INDEX IF NOT EXISTS ix_vt_first_seen ON vulnerability_technology (first_seen_at);

-- ---------------------------------------------------------------------
-- notifications : historique des courriels envoyés
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notifications (
    id            integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind          varchar(20)   NOT NULL,                     -- immediate|digest|test
    recipients    varchar(1000) NOT NULL,
    subject       varchar(300)  NOT NULL,
    body_html     text          NULL,
    alert_count   integer       NOT NULL DEFAULT 0,
    status        varchar(20)   NOT NULL DEFAULT 'pending',   -- pending|sent|failed
    error         text          NULL,
    created_at    timestamptz   NOT NULL DEFAULT now(),
    sent_at       timestamptz   NULL
);
CREATE INDEX IF NOT EXISTS ix_notif_created ON notifications (created_at);

-- ---------------------------------------------------------------------
-- alerts : une alerte par couple (faille, technologie) + escalades KEV
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    id                integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    vulnerability_id  integer       NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    technology_id     integer       NOT NULL REFERENCES technologies(id)    ON DELETE CASCADE,
    kind              varchar(20)   NOT NULL DEFAULT 'new',   -- new (nouvelle faille) | kev (entrée au KEV) | rescored
    severity          varchar(10)   NOT NULL,                 -- criticité calculée (CVSS ajusté KEV/EPSS)
    risk_score        integer       NOT NULL DEFAULT 0,       -- 0..100
    status            varchar(20)   NOT NULL DEFAULT 'new',   -- new|acknowledged|resolved|ignored
    is_baseline       boolean       NOT NULL DEFAULT false,   -- true = trouvée lors de l'inventaire initial
    reason            varchar(500)  NULL,
    notification_id   integer       NULL REFERENCES notifications(id) ON DELETE SET NULL,
    notified_at       timestamptz   NULL,
    status_changed_at timestamptz   NULL,
    status_comment    varchar(500)  NULL,
    created_at        timestamptz   NOT NULL DEFAULT now(),
    CONSTRAINT uq_alert UNIQUE (vulnerability_id, technology_id, kind)
);
CREATE INDEX IF NOT EXISTS ix_alert_status   ON alerts (status);
CREATE INDEX IF NOT EXISTS ix_alert_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS ix_alert_tech     ON alerts (technology_id);
CREATE INDEX IF NOT EXISTS ix_alert_pending  ON alerts (created_at) WHERE notified_at IS NULL;

-- ---------------------------------------------------------------------
-- scan_runs : journal des exécutions du service de surveillance
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_runs (
    id                   integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    trigger_source       varchar(20)  NOT NULL,               -- schedule|manual|startup
    status               varchar(20)  NOT NULL DEFAULT 'running', -- running|success|partial|failed
    technologies_scanned integer      NOT NULL DEFAULT 0,
    vulns_fetched        integer      NOT NULL DEFAULT 0,
    vulns_new            integer      NOT NULL DEFAULT 0,
    links_new            integer      NOT NULL DEFAULT 0,
    kev_updates          integer      NOT NULL DEFAULT 0,
    log                  text         NULL,
    started_at           timestamptz  NOT NULL DEFAULT now(),
    finished_at          timestamptz  NULL
);
CREATE INDEX IF NOT EXISTS ix_scan_started ON scan_runs (started_at);

-- Rang de criticité (tri SQL : CRITICAL d'abord)
CREATE OR REPLACE FUNCTION severity_rank(s text) RETURNS integer
    LANGUAGE sql IMMUTABLE AS
$$ SELECT CASE s WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4 WHEN 'MEDIUM' THEN 3
                 WHEN 'UNKNOWN' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END $$;
