"""Local-first AI helpers for HKSO. LLM calls are optional and explicitly gated."""
import hashlib
import json
import os
import re
import sqlite3
from datetime import date, datetime
from difflib import SequenceMatcher
from pathlib import Path

AI_SCHEMA = '''
CREATE TABLE IF NOT EXISTS ai_analyses (
 id INTEGER PRIMARY KEY, document_id INTEGER NOT NULL REFERENCES documents(id), actor_id INTEGER NOT NULL REFERENCES users(id),
 status TEXT NOT NULL, engine TEXT NOT NULL, extracted_json TEXT NOT NULL DEFAULT '{}', summary TEXT NOT NULL DEFAULT '',
 error TEXT, content_sha256 TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(document_id,content_sha256));
CREATE TABLE IF NOT EXISTS document_chunks (
 id INTEGER PRIMARY KEY, analysis_id INTEGER NOT NULL REFERENCES ai_analyses(id), document_id INTEGER NOT NULL REFERENCES documents(id),
 page_number INTEGER NOT NULL, chunk_index INTEGER NOT NULL, text TEXT NOT NULL, UNIQUE(analysis_id,page_number,chunk_index));
CREATE INDEX IF NOT EXISTS idx_chunks_document ON document_chunks(document_id,page_number);
CREATE TABLE IF NOT EXISTS ai_conversations (
 id INTEGER PRIMARY KEY, creator_id INTEGER NOT NULL REFERENCES users(id), institution_id INTEGER NOT NULL REFERENCES institutions(id),
 application_id INTEGER REFERENCES applications(id), title TEXT NOT NULL DEFAULT 'Document chat', created_at TEXT NOT NULL, cleared_at TEXT);
CREATE TABLE IF NOT EXISTS ai_messages (
 id INTEGER PRIMARY KEY, conversation_id INTEGER NOT NULL REFERENCES ai_conversations(id), role TEXT NOT NULL CHECK(role IN ('user','assistant')),
 content TEXT NOT NULL, citations_json TEXT NOT NULL DEFAULT '[]', engine TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_ai_messages_conversation ON ai_messages(conversation_id,id);
CREATE TABLE IF NOT EXISTS delay_assessments (
 id INTEGER PRIMARY KEY, application_id INTEGER NOT NULL REFERENCES applications(id), assessed_at TEXT NOT NULL, snapshot_key TEXT NOT NULL,
 risk TEXT NOT NULL, reasons_json TEXT NOT NULL, suggested_json TEXT NOT NULL, ack_status TEXT, ack_reason TEXT, ack_by INTEGER REFERENCES users(id), ack_at TEXT,
 UNIQUE(application_id,snapshot_key));
CREATE TABLE IF NOT EXISTS ai_checklist (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', app_type TEXT, academic_year TEXT,
 stage TEXT, required_doc_type TEXT, requirement_id INTEGER REFERENCES requirements(id), active INTEGER NOT NULL DEFAULT 1,
 created_by INTEGER REFERENCES users(id), created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS gap_reviews (
 id INTEGER PRIMARY KEY, application_id INTEGER NOT NULL REFERENCES applications(id), checklist_id INTEGER NOT NULL REFERENCES ai_checklist(id),
 decision TEXT NOT NULL CHECK(decision IN ('Verified','Correction required','Unresolved')), reason TEXT NOT NULL,
 reviewer_id INTEGER NOT NULL REFERENCES users(id), reviewed_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_gap_review_item ON gap_reviews(application_id,checklist_id,reviewed_at DESC);
CREATE TABLE IF NOT EXISTS ai_reports (
 id INTEGER PRIMARY KEY, creator_id INTEGER NOT NULL REFERENCES users(id), report_type TEXT NOT NULL, filters_json TEXT NOT NULL,
 metrics_json TEXT NOT NULL, narrative TEXT NOT NULL, engine TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS renewal_tasks (
 id INTEGER PRIMARY KEY, document_id INTEGER NOT NULL REFERENCES documents(id), institution_id INTEGER NOT NULL REFERENCES institutions(id),
 owner_id INTEGER REFERENCES users(id), status TEXT NOT NULL DEFAULT 'Open' CHECK(status IN ('Open','In progress','Submitted','Completed','Dismissed')),
 due_date TEXT, note TEXT NOT NULL DEFAULT '', created_by INTEGER NOT NULL REFERENCES users(id), created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_renewal_tasks_institution ON renewal_tasks(institution_id,status,due_date);
'''

DATE_FORMATS = ('%Y-%m-%d','%d/%m/%Y','%d-%m-%Y','%d.%m.%Y','%B %d, %Y','%b %d, %Y')
DATE_RE = re.compile(r'\b(?:\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}|(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2},?\s+\d{4})\b', re.I)

def parse_date(text):
    for fmt in DATE_FORMATS:
        try: return datetime.strptime(text.strip().replace(',', ''),fmt.replace(',','')).date().isoformat()
        except ValueError: pass
    return None

def _field(pattern, pages):
    rx=re.compile(pattern,re.I)
    for number,text in enumerate(pages,1):
        match=rx.search(text)
        if match:
            candidate=match.group(1).strip(' :-\t\r\n')[:180]
            if candidate: return {'value':candidate,'page':number,'evidence':text[max(0,match.start()-65):min(len(text),match.end()+110)].strip()[:240]}
    return {'value':None,'page':None,'evidence':None}

def extract_fields(pages):
    text='\n'.join(pages)
    fields={
      'institution_name':_field(r'(?:name\s+of\s+(?:the\s+)?institution|institution\s+name|institute\s+name)\s*[:\-]\s*([^\n]{2,120})',pages),
      'document_type':_field(r'(?:document\s+type|subject|title)\s*[:\-]\s*([^\n]{2,100})',pages),
      'reference_number':_field(r'(?:reference\s*(?:no|number|#)|ref\.?\s*(?:no|#)|file\s+no\.?|application\s+no\.?)\s*[:\-]?\s*([A-Z0-9./_-]{3,50})',pages),
      'issue_date':_field(r'(?:date\s+of\s+issue|issued\s+on|issue\s+date)\s*[:\-]?\s*('+DATE_RE.pattern.strip('\\b')+')',pages),
      'expiry_date':_field(r'(?:valid\s+(?:until|up\s+to|till)|expiry\s+date|expires\s+on|date\s+of\s+expiry)\s*[:\-]?\s*('+DATE_RE.pattern.strip('\\b')+')',pages),
    }
    for key in ('issue_date','expiry_date'):
        val=fields[key]['value']
        if val:
            found=DATE_RE.search(val); iso=parse_date(found.group(0)) if found else None
            fields[key]['value']=iso
            if not iso: fields[key]['evidence']=f"Date text requires human confirmation: {val[:80]}"
    fields['contains_text']=bool(text.strip())
    return fields

def chunk_pages(pages, size=1150, overlap=120):
    chunks=[]
    for page_no,text in enumerate(pages,1):
        clean=re.sub(r'\s+',' ',text).strip()
        if not clean: continue
        start=0; idx=0
        while start<len(clean):
            part=clean[start:start+size]
            if part.strip(): chunks.append((page_no,idx,part))
            idx+=1
            if start+size>=len(clean): break
            start+=size-overlap
    return chunks

def extract_pdf(path, ocr=False):
    try: import pymupdf as fitz
    except ImportError as exc: raise RuntimeError('PDF extraction dependency PyMuPDF is unavailable.') from exc
    try: doc=fitz.open(path)
    except Exception as exc: raise ValueError('The uploaded file is not a readable PDF.') from exc
    if doc.is_encrypted:
        doc.close(); raise ValueError('This PDF is encrypted or password protected.')
    if doc.page_count<1 or doc.page_count>200: doc.close(); raise ValueError('PDF must contain between 1 and 200 pages.')
    pages=[]
    try:
        for page in doc:
            text=page.get_text('text') or ''
            if ocr and len(text.strip())<25:
                try:
                    import pytesseract
                    from PIL import Image
                    import io
                    pix=page.get_pixmap(matrix=fitz.Matrix(1.5,1.5),alpha=False)
                    text=pytesseract.image_to_string(Image.open(io.BytesIO(pix.tobytes('png'))))
                except (ImportError,RuntimeError): pass
            pages.append(text[:100_000])
    finally: doc.close()
    if not any(p.strip() for p in pages): raise ValueError('No readable text was found. This may be a scanned PDF; optional OCR requires Tesseract and pytesseract.')
    return pages

def validate_pdf(path, original_name, max_bytes):
    p=Path(path)
    if p.suffix.lower()!='.pdf' or not str(original_name).lower().endswith('.pdf'): raise ValueError('Document Analyzer accepts PDF files only.')
    if not p.is_file() or p.stat().st_size==0: raise ValueError('The uploaded file is empty.')
    if p.stat().st_size>max_bytes: raise ValueError('The PDF exceeds the configured upload size limit.')
    with p.open('rb') as f: signature=f.read(1024)
    if b'%PDF-' not in signature: raise ValueError('The file content does not have a valid PDF signature.')
    return hashlib.sha256(p.read_bytes()).hexdigest()

def similarity(left,right):
    return SequenceMatcher(None,re.sub(r'\W+','',left or '').lower(),re.sub(r'\W+','',right or '').lower()).ratio()

def retrieve_chunks(conn, query, user, application_id=None, limit=5):
    terms={x.lower() for x in re.findall(r'[\w-]{3,}',query)}
    sql='''SELECT ch.text,ch.page_number,d.id document_id,d.name document_name,d.institution_id,d.application_id
      FROM document_chunks ch JOIN documents d ON d.id=ch.document_id JOIN ai_analyses an ON an.id=ch.analysis_id
      WHERE an.status='complete' AND d.file_name IS NOT NULL'''
    args=[]
    if user.get('role') not in {'Regional Officer','Scrutiny Officer','EVC Coordinator','Committee Member','Bureau Officer','Competent Authority','System Administrator','Auditor'}:
        sql+=' AND d.institution_id=?'; args.append(user.get('institution_id'))
    if application_id is not None:
        inst=conn.execute('SELECT institution_id FROM applications WHERE id=?',(application_id,)).fetchone()
        if not inst: return []
        sql+=' AND (d.application_id=? OR (d.application_id IS NULL AND d.institution_id=?))'; args.extend([application_id,inst['institution_id']])
    rows=conn.execute(sql,args).fetchall(); scored=[]
    for row in rows:
        words={x.lower() for x in re.findall(r'[\w-]{3,}',row['text'])}; score=len(terms&words)
        if score: scored.append((score,row))
    scored.sort(key=lambda x:(-x[0],x[1]['document_id'],x[1]['page_number']))
    return [{'text':row['text'],'page':row['page_number'],'document_id':row['document_id'],'document_name':row['document_name'],'score':score} for score,row in scored[:limit]]

def delay_risk(conn, application):
    today=date.today(); reasons=[]; actions=[]; due=None
    try: high_days=max(0,int(os.getenv('DELAY_HIGH_DAYS','3'))); medium_days=max(high_days,int(os.getenv('DELAY_MEDIUM_DAYS','7'))); stale_days=max(1,int(os.getenv('DELAY_STAGE_STALE_DAYS','14'))); critical_stale=max(stale_days,int(os.getenv('DELAY_STALE_HIGH_DAYS','21')))
    except ValueError: high_days,medium_days,stale_days,critical_stale=3,7,14,21
    try: due=date.fromisoformat(application['stage_due']) if application['stage_due'] else None
    except ValueError: pass
    remaining=(due-today).days if due else None
    last=conn.execute('SELECT created_at FROM transitions WHERE application_id=? ORDER BY id DESC LIMIT 1',(application['id'],)).fetchone()
    since=last['created_at'] if last else application['created_at'];
    try: age=max(0,(today-datetime.fromisoformat(since).date()).days)
    except (ValueError,TypeError): age=0
    pending_compliance=conn.execute("SELECT count(*) FROM compliance WHERE application_id=? AND status NOT IN ('Verified','Rejected')",(application['id'],)).fetchone()[0]
    expired_docs=conn.execute("SELECT count(*) FROM documents WHERE application_id=? AND expiry_date IS NOT NULL AND expiry_date<?",(application['id'],today.isoformat())).fetchone()[0]
    pending_workload=conn.execute("SELECT count(*) FROM applications WHERE assigned_officer=? AND status NOT IN ('Completed','Rejected')",(application['assigned_officer'],)).fetchone()[0] if application['assigned_officer'] else 0
    checklist_gaps=compliance_gaps(conn,application)
    missing_evidence=sum(1 for item in checklist_gaps if item['status'] in {'Missing evidence','Correction required','Expired evidence'})
    returned=application['status']=='Returned'
    if remaining is None: reasons.append('No stage deadline is recorded.'); actions.append('Confirm the configured stage due date.')
    elif remaining<0: reasons.append(f'Stage deadline passed by {abs(remaining)} day(s).'); actions.append('Review the overdue stage and record the next action.')
    elif remaining<=high_days: reasons.append(f'Stage deadline is {remaining} day(s) away.'); actions.append('Check readiness and outstanding evidence before the deadline.')
    elif remaining<=medium_days: reasons.append(f'Stage deadline is {remaining} day(s) away.'); actions.append('Review progress against the upcoming deadline.')
    if age>=stale_days: reasons.append(f'No later workflow event is recorded for {age} day(s).'); actions.append('Review current-stage ownership and workload.')
    if pending_compliance: reasons.append(f'{pending_compliance} compliance item(s) remain unresolved.'); actions.append('Request or verify the pending compliance evidence.')
    if expired_docs: reasons.append(f'{expired_docs} linked document(s) have passed their expiry date.'); actions.append('Request a current version and verify its dates.')
    if missing_evidence: reasons.append(f'{missing_evidence} configured checklist item(s) have missing, expired, or correction-required evidence.'); actions.append('Review the checklist and request or verify the required evidence.')
    if pending_workload>=8: reasons.append(f'The assigned officer has {pending_workload} open application(s) in the current register.'); actions.append('Review officer workload and assignment capacity.')
    if returned: reasons.append('Application is currently returned for correction.'); actions.append('Check correction comments and resubmission readiness.')
    risk='high' if remaining is not None and remaining<0 or remaining is not None and remaining<=high_days or age>=critical_stale else 'medium' if remaining is not None and remaining<=medium_days or age>=stale_days or pending_compliance or expired_docs or missing_evidence or returned or pending_workload>=8 else 'low'
    snap='|'.join([str(application['updated_at']),str(remaining),str(age),str(pending_compliance),str(expired_docs),str(missing_evidence),str(pending_workload),str(application['status'])])
    key=hashlib.sha256(snap.encode()).hexdigest()[:24]
    return {'risk':risk,'reasons':reasons or ['No current deadline or evidence signals indicate elevated delay risk.'],'actions':actions or ['Continue normal workflow monitoring.'],'days_remaining':remaining,'stage_age_days':age,'snapshot_key':key,'method':'Explainable rules; no trained model.'}

def compliance_gaps(conn, application):
    clauses=['active=1']; args=[]
    if application['app_type']: clauses.append('(app_type IS NULL OR app_type=?)'); args.append(application['app_type'])
    if application['academic_year']: clauses.append('(academic_year IS NULL OR academic_year=?)'); args.append(application['academic_year'])
    if application['workflow_id']:
        wf=conn.execute('SELECT stages FROM workflows WHERE id=?',(application['workflow_id'],)).fetchone()
        stage=wf['stages'].split(',')[min(application['current_stage'],len(wf['stages'].split(','))-1)] if wf else None
        if stage: clauses.append('(stage IS NULL OR stage=?)'); args.append(stage)
    checks=conn.execute('SELECT * FROM ai_checklist WHERE '+' AND '.join(clauses)+' ORDER BY id',args).fetchall(); out=[]
    for item in checks:
        evidence=[]; statuses=[]
        if item['requirement_id']:
            comp=conn.execute('SELECT * FROM compliance WHERE application_id=? AND requirement_id=?',(application['id'],item['requirement_id'])).fetchone()
            if comp:
                statuses.append(comp['status']); evidence.append({'kind':'Compliance response','status':comp['status'],'comment':comp['officer_comment']})
        sql='SELECT * FROM documents WHERE institution_id=? AND (application_id=? OR application_id IS NULL)'; dargs=[application['institution_id'],application['id']]
        if item['required_doc_type']: sql+=' AND lower(doc_type)=lower(?)'; dargs.append(item['required_doc_type'])
        docs=conn.execute(sql+' ORDER BY id DESC',dargs).fetchall()
        for d in docs: statuses.append(d['status']); evidence.append({'kind':d['name'],'document_id':d['id'],'status':d['status'],'expiry_date':d['expiry_date']})
        if not evidence: status='Missing evidence'; explanation='No linked compliance response or matching document was found.'; action='Submit the required evidence.'
        elif any(e.get('expiry_date') and e['expiry_date']<date.today().isoformat() for e in evidence): status='Expired evidence'; explanation='At least one linked document has an expiry date before today.'; action='Provide a current document and request verification.'
        elif any(s in {'Correction required','Rejected','Returned'} for s in statuses): status='Correction required'; explanation='A linked submission was returned or requires correction.'; action='Review the officer comments and resubmit.'
        elif any(s in {'Pending','Submitted','Pending verification'} for s in statuses): status='Awaiting verification'; explanation='Evidence exists but has not been verified.'; action='Route the evidence to an authorized reviewer.'
        elif any(s in {'Verified','Valid'} for s in statuses): status='Verified'; explanation='A linked record has a human verification status.'; action='Continue normal monitoring.'
        else: status='Needs review'; explanation='Evidence exists; the recorded status is not conclusive.'; action='Review the evidence and record a decision.'
        review=conn.execute('SELECT gr.*,u.username FROM gap_reviews gr JOIN users u ON u.id=gr.reviewer_id WHERE application_id=? AND checklist_id=? ORDER BY id DESC LIMIT 1',(application['id'],item['id'])).fetchone()
        out.append({'id':item['id'],'name':item['name'],'description':item['description'],'status':status,'explanation':explanation,'action':action,'evidence':evidence,'review':dict(review) if review else None})
    return out
