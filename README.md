# Vigie Sécurité

Surveillance locale et automatisée des failles de sécurité qui touchent **votre** stack technologique.
Tout tourne dans Docker. Le système **informe seulement** : aucun correctif n'est appliqué automatiquement.

```
                 ┌────────────── Internet (lecture seule) ──────────────┐
                 │  NVD (NIST) · CISA KEV · MITRE CVE · OSV.dev · EPSS   │
                 └───────────────────────────┬──────────────────────────┘
                                             │ HTTPS
┌──────────────┐   /api   ┌──────────────┐   │   ┌───────────────────┐
│  frontend    │ ───────► │   backend    │ ◄─┼── │  scanner          │
│ React + Vite │          │  .NET 10 API │   │   │ .NET 10 (worker)  │
│ nginx :3000  │          │  :8080       │   └── │ collecte, normal- │
└──────────────┘          └──────┬───────┘       │ isation, corrél.  │
                                 │  SMTP         └─────────┬─────────┘
                        ┌────────▼───────┐                 │
                        │ Mailpit / SMTP │        ┌────────▼────────┐
                        │ :8025 (web)    │        │ PostgreSQL 17   │
                        └────────────────┘        │ (réseau privé)  │
                                                  └─────────────────┘
```

| Service   | Rôle | Accès |
|-----------|------|-------|
| `db`      | PostgreSQL 17 : stack, failles, alertes, courriels, journal des scans | réseau privé seulement |
| `backend` | API REST C# .NET 10 : corrélation, criticité, alertes, courriels | http://localhost:8080 |
| `scanner` | Service de surveillance C# : NVD, CISA KEV, MITRE, OSV, EPSS | interne |
| `frontend`| Tableau de bord React/Vite servi par nginx | **http://localhost:3000** |
| `mailpit` | Serveur SMTP de test qui capture les courriels (remplace MailHog) | http://localhost:8025 |

Les ports ne sont publiés que sur `127.0.0.1` (pas d'accès depuis le réseau).

---

## 1. Lancer le projet

Prérequis : Docker Desktop (ou Docker Engine + Compose v2), accès HTTPS sortant vers les sources ci-dessus.

```bash
cd vigie-securite
cp .env.example .env          # Windows : copy .env.example .env
# éditer .env : mots de passe, INTERNAL_API_KEY, NVD_API_KEY (recommandé)
docker compose up -d --build
docker compose logs -f scanner   # suivre le premier scan
```

Au démarrage :

1. PostgreSQL crée le schéma (`database/init.sql`).
2. Le backend importe `config/stack.txt` (votre stack).
3. Après 30 s, le scanner lance l'**inventaire initial** de chaque technologie.
4. Les alertes sont créées ; le résumé courriel part à l'heure prévue (par défaut 7 h 30).

> **Clé API NVD** : gratuite sur https://nvd.nist.gov/developers/request-an-api-key.
> Sans clé, le NVD limite à 5 requêtes / 30 s : le premier scan d'une grosse stack peut prendre de 10 à 30 minutes.

Arrêter : `docker compose down` · Tout effacer (BD comprise) : `docker compose down -v`

### Développement sans Docker (optionnel)

```bash
docker compose up -d db mailpit        # décommenter le port 5433 de db dans docker-compose.yml
cd backend && dotnet run               # utilise appsettings.json (localhost:5433)
cd surveillance && dotnet run --urls http://localhost:8081
cd frontend && npm install && npm run dev   # http://localhost:5173, /api relayé vers :8080
```

---

## 2. Ajouter une technologie à surveiller

### A. Fichier `config/stack.txt` (recommandé pour la liste de référence)

Une technologie par ligne : `[préfixe:]nom[@version] [| option=valeur ...]`

```text
os:Ubuntu@22.04
os:Windows Server 2019@10.0.17763.6414     # build Windows = version (winver)
framework:ASP.NET Core@8.0.8
framework:.NET Framework@4.8
runtime:PHP 8.1.2                          # « nom version » accepté aussi
app:WordPress@6.5.2
database:PostgreSQL@16.3
npm:react@18.2.0                           # paquets : requête OSV précise
nuget:Newtonsoft.Json@13.0.1
composer:guzzlehttp/guzzle@7.4.0
docker:nginx:1.25-alpine                   # image Docker : le tag sert de version
lib:MaLib@2.1 | cpe=cpe:2.3:a:monvendeur:malib:*:*:*:*:*:*:*:*
```

| Préfixe | Signification |
|---|---|
| `os:` `framework:` `runtime:` `database:` `web:` `app:` `lib:` | type (sert à l'affichage et au CPE `o`/`a`) |
| `docker:` | image Docker `image:tag` |
| `npm:` `nuget:` `pypi:` `composer:` `maven:` `go:` `cargo:` `gem:` `debian:` `ubuntu:` `alpine:` | paquet d'un écosystème (OSV) |

Options : `cpe=` (identifiant NVD exact), `vendor=`, `product=`, `keywords=`, `name=` (nom affiché), `ecosystem=`, `package=`.

Puis : `docker compose restart backend` (import au démarrage), ou page **Ma stack → Importer une liste**
(bouton « Prévisualiser la normalisation » pour vérifier avant d'enregistrer).
L'import **ajoute et met à jour** (une seule entrée du même produit = changement de version) ; il ne supprime jamais.

### B. Tableau de bord → **Ma stack → Ajouter**

Nom, type, version, et au besoin écosystème/paquet ou CPE.

### C. API

```bash
curl -X POST http://localhost:8080/api/technologies -H "Content-Type: application/json" \
  -d '{"name":"PHP","type":"runtime","version":"8.1.2"}'

curl -X POST http://localhost:8080/api/technologies/import -H "Content-Type: application/json" \
  -d '{"text":"npm:axios@1.6.0\nnuget:Npgsql@8.0.2","dryRun":true}'
```

### Comment la normalisation fonctionne

* Les produits courants (≈ 70 : .NET, ASP.NET Core, PHP, Node.js, WordPress, PostgreSQL, MariaDB, nginx, IIS, jQuery, OpenSSL, Windows Server…) sont traduits en **vendeur:produit CPE** du NVD (`shared/Vigie.Shared/TechnologyNormalizer.cs`, dictionnaire `Catalog`, facile à compléter).
* Un paquet d'écosystème (`npm:`, `nuget:`…) est interrogé **avec sa version exacte** dans OSV (bulletins GitHub, Debian, Ubuntu, Alpine…).
* Produit inconnu sans CPE : recherche par mot-clé dans le NVD, corrélation marquée **probable**. Trouvez la CPE exacte sur https://nvd.nist.gov/products/cpe/search et ajoutez `| cpe=...`.
* **Version vide = toutes les failles du produit** (corrélation « probable »). Mettez toujours une version précise.

### Après une mise à jour

Modifiez la version dans **Ma stack** (ou dans `stack.txt` puis redémarrez le backend) : la corrélation est recalculée
immédiatement et les alertes qui ne s'appliquent plus sont **résolues automatiquement**.

---

## 3. Consulter le tableau de bord

http://localhost:3000

| Page | Contenu |
|---|---|
| **Tableau de bord** | indicateurs (critiques, exploitées KEV, ouvertes, nouvelles 7 j), graphique par criticité, nouvelles alertes par jour, technologies les plus exposées, état de la vigie, bouton « Lancer un scan » |
| **Nouvelles vulnérabilités** | failles détectées dans les dernières 24 h / 7 / 30 / 90 jours |
| **Vulnérabilités** | vue globale filtrable : criticité, technologie, dates de publication, KEV, recherche ; export CSV |
| **Mises à jour à faire** | par technologie : version minimale corrigeant toutes les failles ouvertes, triée par urgence |
| **Alertes** | suivi : nouvelle → prise en compte → résolue / ignorée (actions en lot) |
| **Ma stack** | ajout, modification, import, rescan, suppression |
| **Courriels** | historique, aperçu, courriel de test, envoi immédiat du résumé |
| **Scans** | état du service, planification, journal détaillé de chaque scan |

### Calcul de la criticité (`shared/Vigie.Shared/RiskScorer.cs`)

1. Base = score CVSS (v3.1 > v4.0 > v3.0 > v2). Sans score publié : **Moyenne** par prudence.
2. Présente au catalogue **CISA KEV** (exploitée activement) : au moins **Élevée**, **Critique** si CVSS ≥ 7.
3. **EPSS** ≥ 0,5 (forte probabilité d'exploitation sous 30 jours) : +1 niveau.
4. Score de risque 0-100 = CVSS × 7 + 20 (KEV) + EPSS × 10, × 0,8 si la corrélation est « probable ».

Une faille déjà connue qui **entre au catalogue KEV** génère une alerte d'**escalade** et relève la criticité de l'alerte d'origine.

---

## 4. Configurer le SMTP

Dans `.env` puis `docker compose up -d backend` :

```ini
# Relais interne sans authentification
SMTP_HOST=smtp.mondomaine.local
SMTP_PORT=25
SMTP_ENABLE_SSL=false
SMTP_FROM=vigie-securite@mondomaine.qc.ca
NOTIFY_TO=equipe-securite@mondomaine.qc.ca,moi@mondomaine.qc.ca

# Office 365 / Exchange Online (STARTTLS)
# SMTP_HOST=smtp.office365.com
# SMTP_PORT=587
# SMTP_ENABLE_SSL=true
# SMTP_USER=compte-service@mondomaine.qc.ca
# SMTP_PASSWORD=********
```

| Variable | Rôle | Défaut |
|---|---|---|
| `NOTIFY_ENABLED` | active les courriels | `true` |
| `NOTIFY_TO` | destinataires (virgules) | — |
| `NOTIFY_MIN_SEVERITY` | seuil pour figurer dans un courriel : `CRITICAL` `HIGH` `MEDIUM` `LOW` | `HIGH` |
| `NOTIFY_IMMEDIATE_SEVERITY` | courriel **immédiat** dès ce seuil (`NONE` = jamais) | `CRITICAL` |
| `NOTIFY_FREQUENCY` | résumé : `immediate` `hourly` `daily` `weekly` | `daily` |
| `NOTIFY_DAILY_AT` | heure du résumé (heure locale `TZ`) | `07:30` |
| `NOTIFY_WEEKLY_DAY` | jour du résumé hebdomadaire | `Monday` |
| `NOTIFY_INCLUDE_BASELINE` | détailler les failles de l'inventaire initial (sinon : un résumé par technologie) | `false` |
| `DASHBOARD_URL` | lien dans les courriels | `http://localhost:3000` |

Tester : page **Courriels → Envoyer un courriel de test**, puis ouvrir http://localhost:8025 (Mailpit).

Contenu du courriel : résumé par criticité, technologies touchées, tableau des failles (criticité, lien NVD/OSV, badge KEV
avec échéance CISA, CVSS/EPSS, **action recommandée** = version à installer). Un courriel n'est jamais envoyé deux fois
pour la même alerte ; en cas d'échec SMTP, les alertes repartent au cycle suivant.

---

## 5. Ajuster la fréquence de surveillance

Dans `.env` puis `docker compose up -d scanner` :

```ini
SCAN_INTERVAL_MINUTES=360     # toutes les 6 h (minimum 15)
SCAN_DAILY_AT=05:45           # OU une heure fixe par jour (prioritaire si renseigné)
SCAN_ON_STARTUP=true          # scan au démarrage du conteneur
NVD_INITIAL_LOOKBACK_DAYS=0   # inventaire initial : 0 = tout l'historique, 365 = dernière année
```

* Scan manuel : bouton **Lancer un scan** (tableau de bord ou page Scans), ou `curl -X POST http://localhost:8080/api/scans/trigger`.
* Rescan complet d'une technologie : **Ma stack → Rescanner**.
* Les scans suivants sont **incrémentaux** (failles modifiées depuis le dernier scan réussi, avec 1 jour de chevauchement).
* Désactiver une source : `SOURCE_NVD`, `SOURCE_KEV`, `SOURCE_MITRE`, `SOURCE_OSV`, `SOURCE_EPSS` = `false`.
* Proxy d'entreprise : `HTTPS_PROXY=http://proxy:port` dans `.env`.

---

## 6. API REST (extrait)

Spécification OpenAPI : http://localhost:8080/openapi/v1.json

| Méthode | Route | Description |
|---|---|---|
| GET | `/api/vulnerabilities?severity=CRITICAL,HIGH&technologyId=&from=&to=&kev=true&search=&sort=risk&page=1` | liste filtrée |
| GET | `/api/vulnerabilities/new?days=7` | nouvelles vulnérabilités |
| GET | `/api/vulnerabilities/{id}` | détail + technologies + alertes |
| GET | `/api/vulnerabilities/export` | CSV |
| GET/POST | `/api/technologies` | liste / création |
| PUT/DELETE | `/api/technologies/{id}` | modification / suppression |
| POST | `/api/technologies/import` | import en lot (`dryRun`) |
| GET | `/api/technologies/updates` | mises à jour à faire |
| POST | `/api/technologies/{id}/rescan` · `/recorrelate` | rescan / recorrélation |
| GET | `/api/alerts?status=new,acknowledged&severity=` | alertes |
| PATCH | `/api/alerts/status` | `{ids:[..], status, comment}` |
| POST | `/api/alerts/ingest` | **interne** (scanner, en-tête `X-Api-Key`) |
| GET | `/api/dashboard` | indicateurs et graphiques |
| GET/POST | `/api/notifications` · `/test` · `/send-now` | courriels |
| GET/POST | `/api/scans` · `/trigger` · `/status` | scans |

---

## 7. Arborescence

```
vigie-securite/
├── docker-compose.yml          orchestration (5 services, 2 réseaux, 1 volume)
├── .env.example                configuration à copier en .env
├── config/stack.txt            MA STACK (importée au démarrage)
├── database/init.sql           schéma PostgreSQL
├── shared/Vigie.Shared/        code commun backend + scanner
│   ├── TechnologyNormalizer.cs   ligne texte -> vendeur/produit CPE, écosystème, version
│   ├── VersionComparer.cs        comparaison de versions (semver, rc, epoch…)
│   ├── Correlator.cs             produit + plage de versions -> confirmée / probable
│   ├── AffectedRule.cs           règle normalisée « produit X versions [a, b[ »
│   ├── RiskScorer.cs             criticité CVSS + KEV + EPSS
│   └── Severity.cs, Cpe.cs
├── backend/                    API REST .NET 10 (Dapper + Npgsql)
│   ├── Program.cs, appsettings.json, Dockerfile
│   ├── Controllers/  Vulnerabilities, Technologies, Alerts, Dashboard (+ notifications, scans)
│   ├── Services/     Correlation, Alert, Notification, EmailSender, EmailTemplateBuilder,
│   │                 NotificationScheduler, Technology, Vulnerability, Dashboard, StackFileImporter
│   ├── Models/       Technology, Vulnerability, Alert, Notification, Options
│   └── Data/Db.cs
├── surveillance/               service de surveillance .NET 10
│   ├── Program.cs, ScannerOptions.cs, appsettings.json, Dockerfile
│   ├── Sources/      NvdSource, CisaKevSource, MitreSource, OsvSource, EpssSource, CvssCalculator
│   ├── Services/     ScanOrchestrator (le « scanner »), ScanWorker (planification), ScanRepository, BackendClient
│   └── Models/
└── frontend/                   React 19 + Vite + Recharts, servi par nginx
    ├── Dockerfile, nginx.conf, vite.config.js
    └── src/ pages/ (Dashboard, NewVulnerabilities, Vulnerabilities, Updates, Alerts,
                    Technologies, Notifications, Scans), components/, api.js, styles.css
```

### Schéma PostgreSQL

| Table | Contenu |
|---|---|
| `technologies` | ma stack : type, vendeur/produit CPE, version, écosystème/paquet, dernier scan |
| `vulnerabilities` | failles normalisées : CVSS, EPSS, KEV, CWE, règles `affected` (JSON), versions corrigées |
| `vulnerability_technology` | corrélation : source, confiance, règle appliquée, **version corrigée pour cette techno** |
| `alerts` | une alerte par (faille, technologie, type) : criticité calculée, statut, notification |
| `notifications` | courriels envoyés (HTML conservé) |
| `scan_runs` | journal des scans |

Détails : identifiants `GENERATED ALWAYS AS IDENTITY`, dates en `timestamptz` (UTC), booléens natifs,
`ON CONFLICT` pour les insertions idempotentes, fonction `severity_rank()` pour trier par criticité.

Se connecter à la base (psql, pgAdmin, DBeaver) :

```bash
docker compose exec db psql -U vigie -d vigie
# ou décommenter "127.0.0.1:5433:5432" dans docker-compose.yml, puis Host=localhost Port=5433
```

Sauvegarde / restauration :

```bash
docker compose exec db pg_dump -U vigie -d vigie -Fc > vigie.dump
docker compose exec -T db pg_restore -U vigie -d vigie --clean < vigie.dump
```

---

## 8. Ajouter une source (bulletin fournisseur, flux interne…)

1. Créer `surveillance/Sources/MaSource.cs` qui implémente `ITechnologySource`
   et convertit chaque bulletin en `NormalizedVulnerability` avec des `AffectedRule`.
2. L'enregistrer dans `surveillance/Program.cs` :
   `builder.Services.AddHttpClient<MaSource>(...)` et `AddTransient<ITechnologySource>(sp => sp.GetRequiredService<MaSource>())`.

La fusion, la corrélation, la criticité, les alertes et les courriels s'appliquent automatiquement.

---

## 9. Limites et points d'attention

* **Données envoyées à l'extérieur** : le scanner transmet les **noms et versions** de votre stack au NVD et à OSV
  (aucune autre donnée). Si c'est un enjeu, réduisez la stack aux produits publics ou prévoyez un miroir des flux NVD.
* **Qualité du CPE** : la corrélation NVD dépend du couple vendeur:produit. Vérifiez les produits maison via la prévisualisation d'import.
* **Retard d'analyse du NVD** : les CVE récentes peuvent être sans score ni plages de versions ; MITRE (données du CNA
  et de CISA-ADP) comble l'écart quand c'est possible, sinon la corrélation est « probable ».
* **Images Docker** : l'image est traitée comme le produit principal (ex. `nginx:1.25` = nginx 1.25). Pour inventorier
  les paquets système d'une image, utilisez en plus un scanner d'images (Trivy, Grype) — hors périmètre ici.
* **Windows** : indiquer le numéro de build (ex. `10.0.17763.6414`), sinon toutes les CVE du produit remontent.
* **Sécurité de l'application** : pas d'authentification sur le tableau de bord (ports liés à `127.0.0.1`). Avant
  d'exposer sur un réseau, ajoutez une authentification (ex. reverse proxy avec SSO) et du TLS.
