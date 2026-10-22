import os
import io
import json
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import patch
import pymupdf

import app as hkso
from hkso_ai import compliance_gaps, delay_risk, extract_fields, extract_pdf, retrieve_chunks

class HKSOTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        hkso.app.config.update(TESTING=True,WTF_CSRF_ENABLED=False,SECRET_KEY='test-key',DATABASE=str(Path(self.tmp.name)/'test.sqlite3'),UPLOAD_DIR=str(Path(self.tmp.name)/'uploads'))
        Path(hkso.app.config['UPLOAD_DIR']).mkdir()
        with hkso.app.app_context():
            hkso.initialize_database()
            hkso.seed_demo()
        self.client=hkso.app.test_client()
    def tearDown(self): self.tmp.cleanup()
    def choose_department(self,key): return self.client.post('/select-department',data={'department':key},follow_redirects=True)
    def login(self,user):
        with hkso.app.app_context(): role=hkso.db().execute('SELECT role FROM users WHERE username=?',(user,)).fetchone()['role']
        department=next(key for key,value in hkso.DEPARTMENTS.items() if role in value['roles'])
        self.choose_department(department)
        return self.client.post('/login',data={'username':user,'password':'Demo@123'},follow_redirects=True)
    def test_department_selection_and_dynamic_login_heading(self):
        self.assertEqual(self.client.get('/login').status_code,302)
        page=self.client.get('/select-department'); self.assertEqual(page.status_code,200); self.assertIn(b'Welcome to HKSO',page.data)
        self.choose_department('officer'); page=self.client.get('/login'); self.assertIn(b'Officer / Scrutiny Login',page.data); self.assertIn(b'Change department',page.data)
        self.client.get('/select-department'); self.choose_department('evc'); self.assertIn(b'EVC / Committee Login',self.client.get('/login').data)
    def test_department_matching_mismatch_and_invalid_credentials(self):
        self.choose_department('college')
        invalid=self.client.post('/login',data={'username':'institution_admin','password':'wrong'}); self.assertIn(b'Username or password is incorrect',invalid.data)
        mismatch=self.client.post('/login',data={'username':'system_administrator','password':'Demo@123'}); self.assertIn(b'cannot enter College / Institution',mismatch.data)
        with self.client.session_transaction() as sess: self.assertNotIn('uid',sess)
        self.choose_department('administration'); accepted=self.client.post('/login',data={'username':'system_administrator','password':'Demo@123'},follow_redirects=True)
        self.assertEqual(accepted.status_code,200); self.assertIn(b'Overview',accepted.data)
    def test_department_post_value_is_allowlisted_and_logout_returns_to_selection(self):
        response=self.client.post('/select-department',data={'department':'system_administrator'}); self.assertEqual(response.status_code,400)
        self.choose_department('college'); self.client.post('/login',data={'username':'institution_admin','password':'Demo@123'})
        self.client.post('/logout'); self.assertEqual(self.client.get('/login').status_code,302)
        self.assertEqual(self.client.get('/select-department').status_code,200)
    def test_authentication_and_session(self):
        self.assertEqual(self.client.get('/').status_code,302)
        res=self.login('scrutiny_officer'); self.assertEqual(res.status_code,200); self.assertIn(b'Overview',res.data)
        self.client.post('/logout'); self.assertEqual(self.client.get('/').status_code,302)
    def test_institution_scope(self):
        self.login('institution_admin');
        with hkso.app.app_context(): other=hkso.db().execute("SELECT id FROM applications WHERE institution_id=(SELECT id FROM institutions WHERE code='DEMO-002')").fetchone()[0]
        self.assertEqual(self.client.get(f'/applications/{other}').status_code,404)
    def test_private_document_access_is_institution_scoped(self):
        with hkso.app.app_context():
            c=hkso.db(); other=c.execute("SELECT id FROM institutions WHERE code='DEMO-002'").fetchone()[0]; c.execute('INSERT INTO documents(institution_id,name,doc_type,file_name,created_at) VALUES(?,?,?,?,?)',(other,'Private record','Lease','private-other.pdf',hkso.now())); c.commit()
        self.login('institution_admin'); self.assertEqual(self.client.get('/private-files/private-other.pdf').status_code,404)
    def test_renewal_task_is_persisted_and_duplicate_open_task_prevented(self):
        self.login('institution_admin')
        with hkso.app.app_context():
            c=hkso.db(); doc=c.execute("INSERT INTO documents(institution_id,name,doc_type,expiry_date,created_at) VALUES(1,'Renewal test','Lease',?,?)",((date.today()+timedelta(days=20)).isoformat(),hkso.now())).lastrowid; c.commit()
        payload={'action':'create','document_id':str(doc),'due_date':(date.today()+timedelta(days=10)).isoformat(),'note':'Request replacement'}
        self.client.post('/ai/renewals',data=payload,follow_redirects=True); self.client.post('/ai/renewals',data=payload,follow_redirects=True)
        with hkso.app.app_context():
            c=hkso.db(); self.assertEqual(c.execute('SELECT count(*) FROM renewal_tasks WHERE document_id=?',(doc,)).fetchone()[0],1); self.assertEqual(c.execute("SELECT count(*) FROM notifications WHERE kind='Renewal task' AND institution_id=1").fetchone()[0],1)
    def test_application_create_and_list(self):
        self.login('institution_admin'); res=self.client.post('/applications',data={'title':'Test application','app_type':'Other','academic_year':'2026-27','submission_date':date.today().isoformat()},follow_redirects=True)
        self.assertEqual(res.status_code,200); self.assertIn(b'Test application',res.data)
        with hkso.app.app_context(): self.assertTrue(hkso.db().execute("SELECT 1 FROM applications WHERE title='Test application'").fetchone())
    def test_application_edit(self):
        self.login('institution_admin')
        with hkso.app.app_context(): aid=hkso.db().execute('SELECT id FROM applications WHERE institution_id=(SELECT id FROM institutions WHERE code="DEMO-001") LIMIT 1').fetchone()[0]
        self.assertEqual(self.client.get(f'/applications/{aid}/edit').status_code,200)
        res=self.client.post(f'/applications/{aid}/edit',data={'title':'Edited synthetic application','app_type':'Other','academic_year':'2026-27','submission_date':date.today().isoformat()},follow_redirects=True)
        self.assertEqual(res.status_code,200); self.assertIn(b'Edited synthetic application',res.data)
    def test_transition_role_guard_and_return_reason(self):
        self.login('institution_admin')
        with hkso.app.app_context(): aid=hkso.db().execute('SELECT id FROM applications ORDER BY id LIMIT 1').fetchone()[0]
        denied=self.client.post(f'/applications/{aid}/transition',data={'action':'complete'}); self.assertEqual(denied.status_code,403)
        self.client.post('/logout'); self.login('scrutiny_officer')
        # Complete a Scrutiny stage as its assigned role, then ensure returned cases need a reason.
        with hkso.app.app_context():
            c=hkso.db(); c.execute('UPDATE applications SET workflow_id=(SELECT id FROM workflows WHERE name="Scrutiny only") WHERE id=?',(aid,)); c.commit()
        self.client.post(f'/applications/{aid}/transition',data={'action':'return','reason':'Missing evidence'},follow_redirects=True)
        with hkso.app.app_context(): self.assertEqual(hkso.db().execute('SELECT status FROM applications WHERE id=?',(aid,)).fetchone()[0],'Returned')
        self.client.post(f'/applications/{aid}/transition',data={'action':'resubmit','comment':'Correction submitted'},follow_redirects=True)
        with hkso.app.app_context(): self.assertEqual(hkso.db().execute('SELECT status FROM applications WHERE id=?',(aid,)).fetchone()[0],'In progress')
    def test_compliance_submit_is_not_approval_and_requires_staff_verification(self):
        self.login('institution_compliance_officer')
        with hkso.app.app_context(): cid=hkso.db().execute('SELECT id FROM compliance ORDER BY id LIMIT 1').fetchone()[0]
        self.client.post('/compliance',data={'compliance_id':cid,'action':'submit','response':'Synthetic response'},follow_redirects=True)
        with hkso.app.app_context(): self.assertEqual(hkso.db().execute('SELECT status FROM compliance WHERE id=?',(cid,)).fetchone()[0],'Submitted')
        self.client.post('/logout'); self.login('scrutiny_officer'); self.client.post('/compliance',data={'compliance_id':cid,'decision':'Verified','comment':''},follow_redirects=True)
        with hkso.app.app_context(): self.assertEqual(hkso.db().execute('SELECT status FROM compliance WHERE id=?',(cid,)).fetchone()[0],'Verified')
    def test_expiry_alert_deduplication_and_audit_append_only(self):
        with hkso.app.app_context():
            c=hkso.db(); inst=c.execute("SELECT id FROM institutions WHERE code='DEMO-001'").fetchone()[0]
            c.execute('INSERT INTO documents(institution_id,name,doc_type,expiry_date,created_at) VALUES(?,?,?,?,?)',(inst,'Synthetic lease','Lease',(date.today()-timedelta(days=1)).isoformat(),hkso.now())); c.commit()
        hkso.check_deadlines(); hkso.check_deadlines()
        with hkso.app.app_context():
            c=hkso.db(); self.assertEqual(c.execute("SELECT count(*) FROM notifications WHERE kind='Document expiry'").fetchone()[0],1)
            c.execute("INSERT INTO audit(action,record_type,details,created_at) VALUES('test','test','immutable',?)",(hkso.now(),))
            with self.assertRaises(Exception): c.execute('UPDATE audit SET details="tamper" WHERE id=1')
    @staticmethod
    def make_pdf(text):
        doc=pymupdf.open(); page=doc.new_page(); page.insert_text((50,50),text); data=doc.tobytes(); doc.close(); return data
    def test_analyzer_upload_pdf_extracts_fields_and_stores_chunks(self):
        self.login('institution_admin'); pdf=self.make_pdf('Name of Institution: Sample Institute of Technology\nDocument Type: Lease Agreement\nDate of Issue: 01/04/2024\nValid Until: 31/03/2027\nReference No: AB/12345')
        res=self.client.post('/ai/analyzer',data={'category':'Lease','institution_id':'1','file':(io.BytesIO(pdf),'lease.pdf')},content_type='multipart/form-data',follow_redirects=True)
        self.assertEqual(res.status_code,200); self.assertIn(b'Candidate extraction only',res.data)
        with hkso.app.app_context():
            c=hkso.db(); row=c.execute('SELECT * FROM ai_analyses ORDER BY id DESC LIMIT 1').fetchone(); result=json.loads(row['extracted_json'])
            self.assertEqual(row['status'],'complete'); self.assertEqual(result['fields']['institution_name']['value'],'Sample Institute of Technology'); self.assertEqual(result['fields']['expiry_date']['value'],'2027-03-31'); self.assertGreater(c.execute('SELECT count(*) FROM document_chunks WHERE analysis_id=?',(row['id'],)).fetchone()[0],0)
        chat=self.client.post('/ai/assistant',data={'question':'What expiry date is shown in the lease?'},follow_redirects=True)
        self.assertEqual(chat.status_code,200); self.assertIn(b'Valid Until',chat.data); self.assertIn(b'page 1',chat.data)
    def test_analyzer_rejects_unsafe_file_content_and_extensions(self):
        self.login('institution_admin')
        res=self.client.post('/ai/analyzer',data={'category':'Lease','institution_id':'1','file':(io.BytesIO(b'MZ\x00not a pdf'),'fake.pdf')},content_type='multipart/form-data',follow_redirects=True)
        self.assertEqual(res.status_code,200); self.assertIn(b'valid PDF signature',res.data)
        res=self.client.post('/ai/analyzer',data={'category':'Lease','institution_id':'1','file':(io.BytesIO(b'bad'),'fake.exe')},content_type='multipart/form-data',follow_redirects=True)
        self.assertEqual(res.status_code,200); self.assertIn(b'PDF files only',res.data)
        with hkso.app.app_context(): self.assertEqual(hkso.db().execute('SELECT count(*) FROM documents').fetchone()[0],0)
    def test_pdf_missing_fields_are_unknown_and_encrypted_error_is_explicit(self):
        page='Only a short illustrative lease paragraph.'; fields=extract_fields([page]); self.assertIsNone(fields['expiry_date']['value']); self.assertIsNone(fields['institution_name']['value'])
        pdf=self.make_pdf(''); path=Path(hkso.app.config['UPLOAD_DIR'])/'empty-text.pdf'; path.write_bytes(pdf)
        with self.assertRaisesRegex(ValueError,'No readable text'): extract_pdf(path)
        doc=pymupdf.open(); doc.new_page(); encrypted=doc.tobytes(encryption=pymupdf.PDF_ENCRYPT_AES_256,owner_pw='owner',user_pw='reader'); doc.close(); path.write_bytes(encrypted)
        with self.assertRaisesRegex(ValueError,'encrypted'): extract_pdf(path)
    def test_llm_unavailable_uses_explicit_local_fallback(self):
        with patch.dict(os.environ,{'LLM_API_KEY':'','LLM_ALLOW_DOCUMENTS':'true'}): result=hkso.llm_complete('system','user')
        self.assertIsNone(result[0]); self.assertEqual(result[1],'local-fallback'); self.assertIn('not configured',result[2])
    def test_chat_retrieval_is_institution_scoped(self):
        with hkso.app.app_context():
            c=hkso.db(); local=c.execute("SELECT id FROM institutions WHERE code='DEMO-001'").fetchone()[0]; remote=c.execute("SELECT id FROM institutions WHERE code='DEMO-002'").fetchone()[0]
            ids=[]
            for inst,name in [(local,'local lease'),(remote,'remote lease')]:
                doc=c.execute('INSERT INTO documents(institution_id,name,doc_type,file_name,created_at) VALUES(?,?,?,?,?)',(inst,name,'Lease','synthetic-private.pdf',hkso.now())).lastrowid
                analysis=c.execute("INSERT INTO ai_analyses(document_id,actor_id,status,engine,content_sha256,created_at) VALUES(?,1,'complete','local','hash'+?,?)",(doc,str(inst),hkso.now())).lastrowid
                c.execute('INSERT INTO document_chunks(analysis_id,document_id,page_number,chunk_index,text) VALUES(?,?,?,?,?)',(analysis,doc,1,0,'lease expiry date reference')); ids.append(doc)
            user=dict(c.execute("SELECT * FROM users WHERE username='institution_admin'").fetchone()); results=retrieve_chunks(c,'lease expiry date',user)
            self.assertEqual({r['document_id'] for r in results},{ids[0]})
    def test_compliance_gap_and_delay_rules_are_database_grounded(self):
        with hkso.app.app_context():
            c=hkso.db(); approw=c.execute("SELECT * FROM applications WHERE institution_id=(SELECT id FROM institutions WHERE code='DEMO-001') ORDER BY id LIMIT 1").fetchone()
            req=c.execute('SELECT id FROM requirements ORDER BY id LIMIT 1').fetchone()[0]
            check=c.execute('INSERT INTO ai_checklist(name,requirement_id,created_at) VALUES(?,?,?)',('Test checklist',req,hkso.now())).lastrowid
            gap=compliance_gaps(c,approw)[0]; self.assertIn(gap['status'],{'Awaiting verification','Correction required','Verified'})
            stale=dict(approw); stale['stage_due']=(date.today()-timedelta(days=2)).isoformat(); result=delay_risk(c,stale); self.assertEqual(result['risk'],'high'); self.assertTrue(any('deadline passed' in x.lower() for x in result['reasons']))
    def test_confirm_dates_requires_explicit_human_selection(self):
        self.login('institution_admin')
        with hkso.app.app_context():
            c=hkso.db(); doc=c.execute("INSERT INTO documents(institution_id,name,doc_type,created_at) VALUES(1,'Confirm lease','Lease',?)",(hkso.now(),)).lastrowid
            ana=c.execute("INSERT INTO ai_analyses(document_id,actor_id,status,engine,extracted_json,content_sha256,created_at) VALUES(?,1,'complete','local-rules',?,?,?)",(doc,json.dumps({'fields':{'issue_date':{'value':'2024-01-01'},'expiry_date':{'value':'2027-01-01'}}}),'confirm-hash',hkso.now())).lastrowid
            c.commit()
        self.client.post(f'/ai/analyses/{ana}/confirm-dates',data={},follow_redirects=True)
        with hkso.app.app_context(): self.assertIsNone(hkso.db().execute('SELECT expiry_date FROM documents WHERE id=?',(doc,)).fetchone()[0])
        self.client.post(f'/ai/analyses/{ana}/confirm-dates',data={'confirm_expiry':'yes'},follow_redirects=True)
        with hkso.app.app_context(): self.assertEqual(hkso.db().execute('SELECT expiry_date FROM documents WHERE id=?',(doc,)).fetchone()[0],'2027-01-01')
    def test_report_counts_match_database_and_audit_is_written(self):
        self.login('system_administrator'); res=self.client.post('/ai/reports',data={'report_type':'pendency'},follow_redirects=True); self.assertEqual(res.status_code,200); self.assertIn(b'Database metrics',res.data)
        with hkso.app.app_context():
            c=hkso.db(); report=c.execute('SELECT * FROM ai_reports ORDER BY id DESC LIMIT 1').fetchone(); metrics=json.loads(report['metrics_json']); actual=c.execute('SELECT count(*) FROM applications').fetchone()[0]
            self.assertEqual(metrics['application_total'],actual); self.assertTrue(c.execute("SELECT 1 FROM audit WHERE action='ai_report_generated' AND record_id=?",(report['id'],)).fetchone())
    def test_all_ai_navigation_pages_render(self):
        self.login('system_administrator')
        with hkso.app.app_context(): aid=hkso.db().execute('SELECT id FROM applications ORDER BY id LIMIT 1').fetchone()[0]
        for path in ['/ai/analyzer','/ai/assistant','/ai/delay','/ai/gaps',f'/ai/gaps?application={aid}','/ai/reports','/ai/renewals']:
            with self.subTest(path=path): self.assertEqual(self.client.get(path).status_code,200)
    def test_auditor_can_open_audit_log(self):
        self.login('auditor'); self.assertEqual(self.client.get('/audit').status_code,200)
        with hkso.app.app_context(): cid=hkso.db().execute('SELECT id FROM compliance ORDER BY id LIMIT 1').fetchone()[0]
        self.assertEqual(self.client.post('/compliance',data={'compliance_id':cid,'decision':'Verified'}).status_code,403)

if __name__=='__main__': unittest.main()
