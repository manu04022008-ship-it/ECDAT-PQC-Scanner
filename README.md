# ECDAT — Streamlit Public Web Application

This is the deployment-ready copy of the ECDAT cryptographic discovery and PQC
migration application.

## Included runtime components

- `app.py` — Streamlit entry point
- `scanner.py` — scanner dispatcher
- `repository_scanner.py` — recursive repository scanner
- `container_scanner.py` — Docker scanner (works only where Docker CLI/daemon exists)
- `unified_inventory.py` — unified inventory
- `mosca_engine.py` — quantum-risk calculations
- `pqc_recommendations.py` — PQC recommendations
- `algorithm_patcher.py` — migration patching
- `migration_engine.py` — project migration engine
- `cbom_formatter.py` — CBOM export
- `scanners/` — source, dependency, protocol, binary, config and certificate scanners

## GitHub → Streamlit deployment

1. Create a new GitHub repository.
2. Upload the **contents of this folder** (not the outer folder itself).
3. Confirm `app.py` and `requirements.txt` are in the repository root.
4. In Streamlit Community Cloud, create a new app and select:
   - Repository: your GitHub repository
   - Branch: `main`
   - Main file: `app.py`
5. Deploy.

## Public-web input

For the public web app, use **Source Repository → ZIP Archive** or
**Targeted Asset → Upload Assets**.

The Local Folder option is retained for local desktop use. A browser-hosted
Streamlit app cannot directly browse the visitor's computer filesystem.

Live Docker image scanning is also retained for local/server environments with
a Docker daemon. Streamlit hosting normally does not provide a Docker daemon,
so the Docker scan button is automatically disabled there instead of producing
a runtime error.

## Dependency note

`cryptography` is explicitly included because the certificate scanner imports
the X.509 and asymmetric-key modules from that package.

## Security

Uploaded repository ZIPs are extracted only after validating ZIP paths against
the extraction directory to prevent path traversal.
