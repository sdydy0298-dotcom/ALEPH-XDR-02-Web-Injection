import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {decide} from '../xdr/web-injection/decide.mjs';
import {readAlerts,projectAlert} from '../xdr/web-injection/read-alerts.mjs';
import {respond} from '../xdr/web-injection/respond.mjs';
import {checkAccess} from '../ztna/check.mjs';
import {evaluateAccess} from '../ztna/evaluate.mjs';

const load=async path=>JSON.parse(await readFile(new URL('../'+path,import.meta.url),'utf8'));
const fixture=await load('xdr/fixtures/web-injection.json');
const result=await load('xdr/web-injection/result.json');
const now=new Date('2026-10-12T05:00:00.000Z');
const role={block:0,alert:0,record:0};

test('unaltered official fixture has 26 documented Wazuh-style alerts',()=>{
  assert.equal(fixture.schema,'aleph.xdr.fixture.v1');
  assert.equal(fixture.moduleKey,'web-injection');
  assert.equal(fixture.alerts.length,26);
  assert.equal(new Set(fixture.alerts.map(x=>x.id)).size,26);
  assert.ok(fixture.alerts.every(x=>x.agent.name==='choi-bujang-pc'));
});
test('inspection reader returns one safe line per original alert',async()=>{
  const rows=await readAlerts();
  assert.equal(rows.length,fixture.alerts.length);
  assert.equal(rows[0].source,'203.0.113.10');
  assert.ok(rows.every(row=>Object.keys(row).sort().join(',')==='account,description,level,source,time'));
  const run=spawnSync(process.execPath,['xdr/web-injection/read-alerts.mjs'],{encoding:'utf8'});
  assert.equal(run.status,0,run.stderr);
  assert.equal(run.stdout.trim().split('\n').length,fixture.alerts.length);
  const leaked=projectAlert({data:{srcuser:'Bearer originalsecret'},rule:{level:4,description:'password=pass-sample-value token=token-value'}});
  assert.doesNotMatch(JSON.stringify(leaked),/originalsecret|pass-sample-value|token-value/);
});
test('official judge result contract, repeatable per-event pure decisions',()=>{
  assert.equal(result.schema,'aleph.xdr.result.v1');
  assert.equal(result.moduleKey,'web-injection');
  assert.equal(result.decisions.length,26);
  for(let i=0;i<fixture.alerts.length;i++){
    const item=fixture.alerts[i];
    const actual=decide(item);
    assert.deepEqual(result.decisions[i],{alertId:item.id,...actual});
    assert.ok(actual.confidence>=0&&actual.confidence<=1);
    assert.equal(actual.action,actual.confidence>=.85?'block':actual.confidence>=.5?'alert':'record');
    assert.ok(actual.reason && !/[\r\n]/.test(actual.reason));
    role[actual.action]++;
  }
  assert.deepEqual(role,{block:8,alert:9,record:9});
  assert.deepEqual(result.counts,role);
});
test('original Wazuh categories are classified by behavior, not an answer table',()=>{
  for(const item of fixture.alerts){
    const decision=decide(item);
    if(item.rule.mitre.includes('T1190')&&item.rule.level>=10&&Number(item.data.count)>=8)
      assert.equal(decision.action,'block',item.id);
    else if(item.rule.mitre.includes('T1190'))
      assert.equal(decision.action,'alert',item.id);
    else assert.equal(decision.action,'record',item.id);
  }
});
test('judge file operates offline: no imports, resource access or side effects',async()=>{
  const code=await readFile(new URL('../xdr/web-injection/decide.mjs',import.meta.url),'utf8');
  assert.doesNotMatch(code,/^\s*import(?:\s|[{*"'(])/m);
  assert.doesNotMatch(code,/\b(?:require|readFile|writeFile|fetch)\s*\(/);
  assert.ok(code.includes('const PATTERNS'));
});
test('recorded alert stream, temporary denials and fixed-time expiry',async()=>{
  const log=(await readFile(new URL('../xdr/alerts.log',import.meta.url),'utf8')).trim().split('\n').filter(Boolean);
  const rules=await load('xdr/temporary-deny.json');
  assert.equal(log.length,17);
  assert.equal(rules.length,8);
  assert.deepEqual(new Set(rules.map(x=>x.alertId)).size,8);
  for(const line of log){
    const x=JSON.parse(line);
    assert.ok(x.action==='block'||x.action==='alert');
    assert.ok(x.alertId && x.at && x.reason);
    assert.equal(JSON.stringify(x).includes('password='),false);
  }
  for(const rule of rules){
    assert.equal(rule.action,'deny');
    assert.ok(rule.alertId && rule.expiresAt && rule.reason);
    assert.equal((await evaluateAccess(rule.source,now)).action,'deny');
    assert.equal((await evaluateAccess(rule.source,now.getTime()+16*60_000)).action,'allow');
  }
});
test('no user classified normal or ambiguous gets a denied source',async()=>{
  for(const item of fixture.alerts){
    const response=await evaluateAccess(item.data.srcip,now);
    if(decide(item).action!=='block')assert.equal(response.action,'allow',item.id);
  }
  const rules=await load('xdr/temporary-deny.json');
  assert.equal(checkAccess('192.0.2.70',rules,now).action,'allow');
  assert.equal(checkAccess('192.0.2.70',[],now,{deny:[{source:'192.0.2.70'}]}).action,'deny');
});
test('forged block decision for normal event cannot cause denial',async()=>{
  const normal=fixture.alerts.find(x=>x.id==='wi-18');
  const reply=await respond(normal,{action:'block',confidence:.99,reason:'forged'}, {now,persist:false});
  assert.equal(reply.rules.length,0);
  assert.equal(reply.access.action,'allow');
});
const example=(url,count=1,level=8,mitre=['T1190'])=>({
 id:'edge-01',rule:{level,description:'Repeated suspicious web request',mitre},
 data:{srcip:'198.51.100.80',url,count:String(count)}
});
for(const [name,event,expected] of [
 ['repeated SQL UNION SELECT',example('/search?q=1%20UNION%20SELECT%20user',12,12),'block'],
 ['repeated XSS script',example('/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E',10,11),'block'],
 ['repeated encoded traversal',example('/files?p=%2e%2e%2f%2e%2e%2fvar%2flog',8,12),'block'],
 ['repeated shell separators',example('/search?q=x%3Bwhoami',11,12),'block'],
 ['single SQL attempt',example('/search?q=1%20UNION%20SELECT%20user',1,12),'alert'],
 ['single XSS marker',example('/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E',1,8),'alert'],
 ['script is a class name',example('/search?q=script-class',1,7),'alert'],
 ['select is a class name with no attack tag',example('/search?q=select-course',1,3,[]),'record'],
 ['up is a simple filename',example('/files?p=up-notes',1,3,[]),'record'],
 ['unrelated plain browse',example('/api/notes',1,3,[]),'record'],
 ['invalid source must not block',{id:'edge-invalid',rule:{level:12,mitre:['T1190'],description:'SQL 구문을 12번 반복'},data:{srcip:'999.999.999.999',count:'12',url:'/api?q=doc-sql'}},'alert']
]){
 test(name,()=>assert.equal(decide(event).action,expected,JSON.stringify(decide(event))));
}
