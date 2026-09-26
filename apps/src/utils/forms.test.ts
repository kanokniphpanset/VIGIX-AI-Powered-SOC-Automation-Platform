import test from 'node:test'
import assert from 'node:assert/strict'
import { formPayload } from './forms.ts'
import { incidentsApi, workflowApi, knowledgeApi, alertsApi, settingsApi } from '../api/vigix.ts'
import { setLocale } from '../i18n/locale.ts'

// These assertions check the English wording (the UI default is Thai; Thai text is covered by i18n/locale.test.ts).
setLocale('en')

test('forms require values, validate numbers/enums and preserve multiline notes', () => {
  assert.throws(() => formPayload([{key:'reason',label:'Reason',required:true}], {reason:' '}), /required/)
  assert.throws(() => formPayload([{key:'count',label:'Count',type:'number',min:0}], {count:-1}))
  assert.throws(() => formPayload([{key:'type',label:'Type',options:['IPV4']}], {type:'invented'}))
  assert.deepEqual(formPayload([{key:'query',label:'Query',type:'textarea'},{key:'hosts',label:'Hosts',type:'lines'},{key:'flag',label:'Flag',type:'checkbox'}], {query:'one\ntwo',hosts:'host1\n\nhost2',flag:false}), {query:'one\ntwo',hosts:['host1','host2'],flag:false})
})
test('new manual and knowledge controls target real endpoints with only supplied fields', async () => {
  const original=globalThis.fetch; const calls: {url:string; method:string; body:unknown}[]=[]
  globalThis.fetch=async(url,init)=>{calls.push({url:String(url),method:String(init?.method),body:init?.body?JSON.parse(String(init.body)):null});return new Response('{}')}
  try {
    await incidentsApi.addEvidence('i',{type:'ANALYST_NOTE',source:'ANALYST',title:'New note'})
    await incidentsApi.addIoc('i',{iocType:'IPV4',iocValue:'192.0.2.1',source:'Analyst'})
    await incidentsApi.updateStatus('i','resolved')
    await workflowApi.submitVerification('i',{responseId:'r',query:'analyst query',matchingEvents:0,threatContained:true})
    await knowledgeApi.create('runbooks',{code:'RB-1',name:'Runbook',procedure:['step']})
    await knowledgeApi.update('policies','p',{name:'Updated'})
    await knowledgeApi.toggle('actions','a',false)
    await knowledgeApi.evaluate({severity:'HIGH'})
    await settingsApi.setNotificationRecipient('IR_TEAM',null)
    assert.deepEqual(calls.map(c=>c.url), ['/api/v1/investigations/i/evidence','/api/v1/investigations/i/iocs','/api/v1/incidents/i/status','/api/incidents/i/verifications','/api/runbooks','/api/policies/p','/api/actions/a/disable','/api/policies/evaluate','/api/v1/settings/notification-recipients/IR_TEAM'])
    assert.deepEqual(calls[2]?.body,{status:'resolved'})
    assert.equal('result' in (calls[3]?.body as object),false)
    assert.ok(calls.every(c=>!c.url.includes('rehunt')&&!c.url.includes('send')))
  } finally {globalThis.fetch=original}
})
test('ticket pagination uses server limit/offset and incident filter', async()=>{
  const original=globalThis.fetch;let url=''
  globalThis.fetch=async u=>{url=String(u);return new Response('{}')}
  try{await workflowApi.allResponses(25,50,'incident');assert.equal(url,'/api/responses?limit=25&offset=50&incidentId=incident')}
  finally{globalThis.fetch=original}
})
