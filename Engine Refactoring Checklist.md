# Engine Refactoring Checklist

## Context

This refactoring migrates all 33 engines from returning raw `dict | None` to typed `BaseReport` subclasses. The goal is type safety, consistent error handling, and template rendering that uses object attributes instead of dict key lookups.

**Pattern**: Each engine becomes `class XEngine(BaseEngine[XReport])` with a `models/x.py` file defining `XReport(BaseReport)`.

**Base classes**: `models/report.py` (BaseReport), `models/base_engine.py` (BaseEngine[R])

---

## Current Status

**Fully done** (8 engines — model + typed engine + tests pass):

| Engine | Model | Typed Engine | Tests | Contributions Validation |
|--------|-------|-------------|-------|-------|
| abuseipdb | ✅ | ✅ | ✅ | ✅ | 
| abusix | ✅ | ✅ | ✅ | ✅ | 
| alienvault | ✅ | ✅ | ✅ | ✅ | 
| bad_asn | ✅ | ✅ | ✅ | ✅ | 
| chrome_extension | ✅ | ✅ | ✅ | ✅ |  
| criminalip | ✅ | ✅ | ✅ | ✅ |  
| crowdstrike | ✅ | ✅ | ✅ | ✅ |  
| crtsh | ✅ | ✅ | ✅ | ✅ | 
| dfir_iris | ✅ | ✅ | ✅ | ✅ |
| ipinfo | ✅ | ✅ | ✅ | ✅ |
| github | ✅ | ✅ | ✅ | ✅ |

**In progress** (model created, engine/tests partially refactored):

| Engine | Model | Typed Engine | Tests |
|--------|-------|-------------|-------|
| google_dns | ✅ | ❌ | ❌ |
| hudsonrock | ✅ | ❌ | ❌ |
| ipapi | ✅ | ✅ (analyze only) | ✅ (analyze; create_export_row still dict-based) |

**Not started** (24 engines — includes 3 added from main in 2026-05 merge):

| Engine | Model | Typed Engine | Tests | Template Validation |
|--------|-------|-------------|-------|-------|
| google | ❌ | ❌ | ❌ | X |
| google_safe_browsing | ❌ | ❌ | ❌ | X |
| hister | ❌ | ❌ | ❌ | X |
| ioc_one | ❌ | ❌ | ❌ | X |
| ipquery | ❌ | ❌ | ❌ | X |
| microsoft_defender_for_endpoint | ❌ | ❌ | ❌ | X |
| misp | ❌ | ❌ | ❌ | X |
| misp_feedback | ❌ | ❌ | ❌ | X |
| opencti | ❌ | ❌ | ❌ | X |
| phishtank | ❌ | ❌ | ❌ | X |
| rdap | ❌ | ❌ | ❌ | X |
| rdap_whois | ❌ | ❌ | ❌ | X |
| reverse_dns | ❌ | ❌ | ❌ | X |
| reversinglabs_spectra_analyze | ❌ | ❌ | ❌ | X |
| rosti | ❌ | ❌ | ❌ | X |
| shodan | ❌ | ❌ | ❌ | X |
| spur_us | ❌ | ❌ | ❌ | X |
| threatfox | ❌ | ❌ | ❌ | X |
| urlscan | ❌ | ❌ | ❌ | X |
| ransomware_live | ❌ | ❌ | ❌ | X |
| virustotal | ❌ | ❌ | ❌ | X |
| webscout | ❌ | ❌ | ❌ | X |

### Instructions for Resuming Claude session

1. Start a new conversation in this project directory
2. Say something like: "Let's continue the engine checklist audit — check my memory for where we left off"
3. Claude will load project_engine_checklist_audit.md and know to pick up alphabetically after ipinfo, apply the same evaluation pattern, and be aware of the gaps already
identified and the rules established (no-key N/A, no-external-API N/A, etc.)

The memory also captures the open gaps for chrome_extension, criminalip, and crowdstrike so those don't get lost between sessions.

---

## Implementation Steps (per engine)

For each not-started engine:

1. Create `models/<engine_name>.py` with `XReport(BaseReport)` — fields must match the template attribute names exactly
2. Update `engines/<engine_name>.py`:
   - Change `class XEngine(BaseEngine):` → `class XEngine(BaseEngine[XReport]):`
   - Change `analyze()` return type to `XReport`
   - Replace `return {fields}` → `return XReport(success=True, **fields)`
   - Replace `return None` → `return XReport(success=False, error="...")`
   - Update `create_export_row(self, analysis_result: XReport | None)` signature
3. Update `tests/engines/test_<engine_name>.py`:
   - Add `from models.<engine_name> import XReport`
   - Change `result["field"]` → `result.field`
   - Add `assert isinstance(result, XReport)` checks
4. Validate Template Displays Correctly after Refactoring
   - Check template validation for `*_card.html` and `*_table.html`
   - Check template validation for `graph.html`
   - Check template validation for export

For all engines:

### Secrets

* Make sure that your engine config/secret variable (if relevant) is added to `utils/config.py`.

### Configuration & Secrets
* Make sure any API key or configuration needed for the engine is added to `secrets_sample.json` and `.env.sample`.
* Make sure you can save secrets using the `config.html` page.
* Make sure that the templating of variables in `docker-compose.yml` is correct.

### UI & Frontend
* Make sure the engine result can be copied to clipboard using the GUI in `static/format_results.js`.
* Make sure every template in `templates/` has corresponding engine result template in `templates/engines_layouts/` - `engine_card.html` and `engine_table.html`.
* Make sure the engine is added in `display_cards.html` and `display_table.html`.
* Make sure the engine is in the GUI form `index.html` with relevant description - alphabetic order.
* Make sure the engine is usable in the graph view in `graph.html`.

### Documentation
* Make sure the engine is documented in `docs/api-keys/Get-Engine-API-key.md` if relevant.
* Make sure to add the link to the API key guide in `docs/index.md` if relevant.
* Make sure the engine is documented in `docs/quick-start/API-usage-and-engine-names.md`.
* Make sure to add the page to the sidebar in `mkdocs.yml`.
* Make sure the engine is documented in `docs/quick-start/Quick-start-&-Installation.md` in the `secrets.json` example.
* Make sure to add any environment variable needed to `docs/quick-start/Advanced-options-for-deployment.md` in the `docker compose` example.
* Make sure to add references in the README.md (secrets.json example and URL of the new engine in the "API and third-party services" section).


---

## Model Field Reference

Field names must match what the templates reference. Summary per engine:

| Engine | Model Class | Key Fields |
|--------|-------------|------------|
| alienvault | `AlienvaultReport` | *(model exists — check `models/alienvault.py`)* |
| dfir_iris | `DfirIrisReport` | `reports` (list), `links` |
| github | `GithubReport` | `results` (list of `{url, title, description}`) |
| google | `GoogleReport` | `results` (list of `{url, title, description}`) |
| google_dns | `GoogleDnsReport` | `Answer` (list of DnsRecord: `type_name`, `data`, `TTL`, `present`, `parsed`) |
| google_safe_browsing | `GoogleSafeBrowsingReport` | `threat_found`, `details` |
| hudsonrock | `HudsonRockReport` | `stealers`, `total`, `totalStealers`, `employees`, `users`, `third_parties`, `totalUrls`, `last_employee_compromised`, `last_user_compromised`, `is_shopify`, `applications`, `stealerFamilies` (dict), `stats` (with `employees_urls`, `clients_urls`) |
| ioc_one | `IocOneReport` | `results` (list of `{source, header, title}`), `link`, `count` |
| ipapi | `IpapiReport` | `ip`, `is_vpn`, `is_tor`, `is_proxy`, `is_abuser`, nested `location` (`city`, `state`, `country`, `country_code`), `asn` (`asn`, `org`), `vpn` (`service`, `url`) |
| ipquery | `IpQueryReport` | `ip`, `geolocation`, `country_code`, `country_name`, `isp`, `asn`, `is_vpn`, `is_tor`, `is_proxy`, `risk_score`, `link` |
| microsoft_defender_for_endpoint | `MdeReport` | `orgPrevalence`, `orgFirstSeen`, `orgLastSeen`, `link`, `issuer`, `signer`, `isValidCertificate`, `filePublisher`, `fileProductName`, `determinationType`, `determinationValue` |
| misp | `MispReport` | `count`, `events` (list of `{title, url, timestamp}`), `link`, `first_seen`, `last_seen` |
| opencti | `OpenCtiReport` | `entity_counts` (dict), `global_count`, `search_link`, `latest_created_at`, `latest_indicator_link`, `latest_indicator_name`, `x_opencti_score`, `revoked`, `valid_from`, `valid_until`, `confidence` |
| phishtank | `PhishtankReport` | `in_database`, `verified`, `valid`, `phish_detail_page` |
| rdap | `RdapReport` | `abuse_contact`, `registrar`, `organization`, `registrant`, `registrant_email`, `name_servers` (list), `creation_date`, `expiration_date`, `update_date`, `link` |
| rdap_whois | `RdapWhoisReport` | `abuse_contact`, `registrar`, `organization`, `registrant`, `registrant_email`, `emails` (list), `name_servers` (list), `creation_date`, `expiration_date`, `update_date`, `link`, `data_source`, `registrant_country` |
| reverse_dns | `ReverseDnsReport` | `reverse_dns` (list[str]) |
| reversinglabs_spectra_analyze | `RlAnalyzeReport` | `report_type`, `report_color`, `reports`, `malicious`, `suspicious`, `total_files`, `malicious_files`, `suspicious_files`, `threats` (list), `link`, `classification`, `riskscore`, `scanners` |
| rosti | `RostiReport` | `count`, `results` (list of RostiItem: `value`, `type`, `category`, `date`, `comment`, `ids`, `report`, `link`, `timestamp`, `risk`, `id`), `total`, `has_more` |
| shodan | `ShodanReport` | `ports` (list), `tags` (list), `link` |
| spur_us | `SpurUsReport` | engine `name` = `"spur"`, fields: `link`, `tunnels` |
| threatfox | `ThreatFoxReport` | `count`, `malware_printable` (list), `link` |
| urlscan | `UrlscanReport` | `scan_count`, `top_domains` (list of `{domain, count}`), `link` |
| virustotal | `VirusTotalReport` | `detection_ratio`, `total_malicious`, `link`, `community_score` |
| webscout | `WebscoutReport` | `ip`, `risk_score`, `is_proxy`, `is_tor`, `is_vpn`, `country_code`, `country_name`, `location`, `hostnames` (list), `domains_on_ip`, `network_type`, `network_provider`, `network_service`, `network_service_region`, `network_provider_services` (list), `behavior` (list), `as_org`, `asn`, `description` |

---

## Verification

After each batch, run:

```bash
python -m pytest tests/engines/ -q
```

All tests must pass. Baseline: **1169 tests passing**.
