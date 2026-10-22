# HKSO — AICTE Approval Workflow and Institutional Compliance Monitoring

HKSO is a Flask and SQLite workflow aid for institutional approvals, scrutiny stages, EVC visits, compliance evidence, document validity, reports, and audit history. It is not an official AICTE service and does not encode official approval requirements. Demo data and checklist examples are synthetic and illustrative. AI output is unverified decision support; all statutory decisions remain with authorized human officials.

## Windows setup

From PowerShell in this project directory:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Set a private, random `SECRET_KEY` in `.env` before using the app beyond local demo use. A value can be generated with:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

Start the application with `python app.py`, then open <http://127.0.0.1:5000>. On first launch HKSO creates or safely extends `instance/hkso.sqlite3`; existing tables and data are retained. Uploaded files remain in `private_uploads/` and are served only through an authenticated institution-scoped route. Back up and protect both locations.

Unauthenticated users first choose a department at `/select-department`. This selection only routes to the appropriate sign-in page; HKSO verifies the account's database role against the selected department after password authentication. The four entry groups map the existing roles as follows: College / Institution (Institution Admin, Institution Compliance Officer), Administration (System Administrator, Auditor), Officer / Scrutiny (Regional Officer, Scrutiny Officer, Bureau Officer, Competent Authority), and EVC / Committee (EVC Coordinator, Committee Member). Auditor access remains read-only where enforced by existing routes.

### Demo accounts

All roles use `Demo@123` on the seeded database. Choose the matching department before entering a demo username. Change demo passwords before any shared deployment.

| Role | Username |
|---|---|
| Institution Admin | `institution_admin` |
| Institution Compliance Officer | `institution_compliance_officer` |
| Regional Officer | `regional_officer` |
| Scrutiny Officer | `scrutiny_officer` |
| EVC Coordinator | `evc_coordinator` |
| Committee Member | `committee_member` |
| Bureau Officer | `bureau_officer` |
| Competent Authority | `competent_authority` |
| System Administrator | `system_administrator` |
| Auditor | `auditor` |

Sample institutions are `DEMO-001` and `DEMO-002`. Institution users are restricted to their own institution. Official staff accounts have cross-institution access according to role checks; auditors are read-only on the AI action routes.

## Existing HKSO features

- Session authentication, password hashing, CSRF protection, server-side roles and institution scoping.
- Application registration/editing, filters, pagination, workflow stage history, authorized transitions, returns and resubmissions.
- Configurable ordered workflow stage sequences, EVC scheduling and history, compliance submission and separate human verification.
- Private document register, renewal versions, in-app notifications, dashboard, reports, CSV export and append-only audit events.

## Six integrated AI tools

1. **Document Analyzer** — accepts PDF only, validates the filename, size, PDF signature and parseability, extracts local text with PyMuPDF, and detects candidate institution name, document type, issue/expiry dates and reference number with page excerpts. It records empty/unreadable/encrypted extraction failures, stores page chunks for retrieval, and flags absent fields, institution-name mismatch, expired dates and duplicate file hashes. OCR is optional; scanned PDFs need a local Tesseract installation and `pytesseract`/Pillow.
2. **AI Assistant** — retrieves keyword-ranked text chunks only from documents the logged-in user may access, plus application history, compliance and configured gap records. It cites document/page or record sources. Without an enabled model it returns cited source excerpts and explicitly reports insufficient evidence when retrieval finds nothing. Conversations are private to their creator and can be cleared; `AI_CHAT_RETENTION_DAYS` controls automatic cleanup.
3. **Delay Early Warning** — recalculates transparent low/medium/high rules from stage deadlines, time since the latest workflow event, pending compliance, expired/missing checklist evidence and assigned officer workload. Warnings include reasons and suggested review actions. Authorized staff can acknowledge or dismiss with a required reason. No predictive model is trained.
4. **Compliance Gap Detector** — compares configured checklist entries with real compliance and document records; statuses include missing evidence, awaiting verification, correction required, expired evidence and verified. System Administrators can add illustrative checklist items; authorized staff record human review decisions. No legal conclusion is inferred from model output.
5. **AI Reports** — generates deterministic database metrics for pendency, daily/weekly summaries, overdue work, application history, workload, compliance gaps, expiry/renewals and EVC records. It stores report metadata, supports CSV export, and lets a reviewer edit the draft narrative. Reminder text is drafted only; it is never sent by HKSO.
6. **Document Renewal Assistant** — calculates expiry days using Python dates and configurable windows, shows extracted date/page candidates, requires an explicit human action before writing candidate dates to the register, creates deduplicated renewal tasks/reminders, and preserves separate task, replacement-document and verification statuses.

## LLM configuration and privacy

The six tools remain functional without a model. Local PDF extraction, retrieval, risk rules, gap comparison and report metrics are deterministic. No trained scikit-learn prediction model is included because this demo has no adequate labelled historical dataset.

An optional OpenAI-compatible chat-completions provider can summarize document excerpts, answer from retrieved sources and draft report narratives. Configure `LLM_API_BASE`, `LLM_MODEL`, and `LLM_API_KEY`. **External processing is disabled by default.** Set `LLM_ALLOW_DOCUMENTS=true` only after the deployment is authorized to transmit the selected document excerpts and report data to that provider. Requests have a bounded timeout (`LLM_TIMEOUT`); missing credentials, provider errors, timeouts and invalid responses fall back to local behavior. The application does not claim a model was used when it was unavailable. API keys are read only from the environment and are never written to the database or audit log.

## Configuration

`ALERT_DAYS` controls application/compliance/EVC/document reminders. `RENEWAL_ALERT_DAYS` controls document expiry and renewal task reminders. `DELAY_HIGH_DAYS`, `DELAY_MEDIUM_DAYS`, `DELAY_STAGE_STALE_DAYS`, and `DELAY_STALE_HIGH_DAYS` tune explainable delay rules. `MAX_CONTENT_LENGTH` caps uploads (10 MB by default), and the analyzer limits PDFs to 200 pages. `AI_OCR_ENABLED=true` attempts local OCR when PyMuPDF finds no page text; install Tesseract separately and make it available to the Python process. OCR does not send files externally.

The existing hourly in-process deadline task now also checks AI renewal reminders and chat retention. This suits a single-process prototype. For production, use a managed scheduler/worker and production WSGI server, configure HTTPS, backups, retention, monitoring, and operational access controls.

## Database migration

At startup HKSO executes the existing `CREATE TABLE IF NOT EXISTS` schema, adds only `documents.content_sha256` and `documents.requirement_id` when missing, and creates the AI tables/indexes if absent. It does not drop or reset existing records. A clearly labelled synthetic checklist item is seeded only when the AI checklist is empty.

## Tests

Run `python -m unittest discover -s tests -v`. Tests use isolated temporary SQLite databases and synthetic PDFs. Coverage includes department selection/login role matching and mismatch rejection, existing application CRUD/workflow behavior, institution and private-file isolation, PDF validation/extraction and evidence chunks, missing/encrypted file handling, local LLM fallback, institution-scoped retrieval/chat citations, delay and gap calculations, explicit date confirmation, renewal-task duplicate prevention, report metric parity, reminders and audit immutability.

## Known limits

- Live LLM behavior has not been claimed or exercised unless you provide an authorized provider configuration. The default environment has no model credentials; normal operation uses local rules and cited excerpts.
- OCR is an optional system dependency and is disabled by default. Unsupported office formats remain available in the regular Documents module, while the analyzer requires PDF.
- The delay warning is an explainable rules engine, not a trained prediction. Rule thresholds are configurable; illustrative sample values are not official deadlines.
- Checklist items can be added by the System Administrator; requirement language must come from your organization. Report narratives and all extracted fields require review.
- CSV is implemented; PDF report export is not. The scheduler is in-process and should be replaced by a managed worker for multi-process deployments.
- No email or SMS transport is configured. Notices remain in HKSO.
