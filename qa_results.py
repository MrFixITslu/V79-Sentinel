"""Local read-only QA report and screenshot serving, with strict path validation."""
from __future__ import annotations
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent
LATEST = ROOT / 'data' / 'qa-latest.json'
RUNS = ROOT / 'data' / 'qa-runs'
RUN_ID = re.compile(r'^\d{8}T\d{6}Z$')
SCREENSHOT = re.compile(r'^[a-z0-9]+(?:-[a-z0-9]+)*-(?:desktop|mobile)\.png$')
MAX_REPORT = 256 * 1024
MAX_IMAGE = 4 * 1024 * 1024

def load_qa_latest():
    """Return only fully-completed summary; never label partial tests as complete."""
    if not LATEST.is_file():
        return {'state':'not-run','message':'No complete full-ecosystem QA report yet. Manual checks only.'}
    if LATEST.stat().st_size > MAX_REPORT:
        return {'state':'error','message':'QA report exceeds size limit'}
    try:
        data = json.loads(LATEST.read_text(encoding='utf-8'))
        if not data.get('complete') or not RUN_ID.fullmatch(data.get('runId','')):
            return {'state':'error','message':'Latest QA report is incomplete or invalid'}
        if data.get('mode')!='public-browser-qa' or not isinstance(data.get('results'),list):
            return {'state':'error','message':'Unsupported QA report format'}
        if len(data['results']) > 40:
            return {'state':'error','message':'QA report has unexpected record count'}
        data['state']='complete'
        return data
    except (OSError,ValueError,TypeError):
        return {'state':'error','message':'Cannot read latest QA result'}

def screenshot(run_id, name):
    """Only files explicitly listed in a report can be viewed."""
    if not isinstance(run_id,str) or not RUN_ID.fullmatch(run_id):
        return None
    if not isinstance(name,str) or not SCREENSHOT.fullmatch(name):
        return None
    run_dir = RUNS / run_id
    report = run_dir / 'report.json'
    if not report.is_file() or report.stat().st_size > MAX_REPORT:
        return None
    try:
        doc=json.loads(report.read_text(encoding='utf-8'))
        if doc.get('runId') != run_id:
            return None
        valid={r.get('screenshot') for r in doc.get('results',[])
               if isinstance(r,dict)}
        if name not in valid:
            return None
        candidate=run_dir / name
        if candidate.is_symlink() or not candidate.is_file():
            return None
        if not 0 < candidate.stat().st_size < MAX_IMAGE:
            return None
        return candidate.read_bytes()
    except (OSError,ValueError,TypeError):
        return None
