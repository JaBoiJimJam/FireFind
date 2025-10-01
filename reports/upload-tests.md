# Drag-and-Drop Upload Smoke Test

**Test date:** 2025-10-01 03:24 UTC

## Environment
- Backend/frontend launched locally with `./start_dev.sh` (FastAPI + static frontend).
- Browser automation executed with Playwright Python (`playwright==1.55.0`, Chromium headless).
- Sample files: `reports/test-files/sample1.csv` and `reports/test-files/sample2.xlsx`.

## Steps
1. Started the development server via `./start_dev.sh` and confirmed FastAPI startup logs.
2. Navigated to `http://127.0.0.1:8000` with Playwright once the server reported readiness.
3. Uploaded the CSV and XLSX sample files through the drag-and-drop panel by targeting the hidden file input backing the drop zone.
4. Observed the rendered file cards in the "Files" section and verified the "START SECURITY SCAN" CTA state.
5. Captured artifacts and collected logs for review.

## Results
- File list populated with the two uploaded fixtures and the files section scrolled into view.
- "START SECURITY SCAN" button was enabled once files were present.
- No JavaScript exceptions were thrown, but the browser console reported a blocked external resource (`net::ERR_CERT_AUTHORITY_INVALID`) when loading Google Fonts.
- FastAPI server logs showed only successful `GET` requests for static assets (no `/api/scan` calls were triggered during this test).

## Artifacts
- Screenshot: `reports/artifacts/upload-page.png`
- Browser console log: `reports/artifacts/browser-console.log`
- Structured run output: `reports/artifacts/upload-run.json`
- Server log excerpt: `reports/artifacts/server-log.txt`

## Follow-ups / Notes
- Investigate whether the Google Fonts request should be proxied or bundled locally to avoid certificate warnings in restricted environments.
- Extend coverage with manual drag-and-drop gestures (not just file input) and trigger a scan to validate `/api/scan` handling once backend expectations are finalized.
- Consider assertions around duplicate filename handling and error messaging for unsupported file types in future runs.
