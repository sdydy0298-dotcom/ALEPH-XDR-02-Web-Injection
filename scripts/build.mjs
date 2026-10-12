import {readFile,writeFile,copyFile,mkdir} from 'node:fs/promises';
const root=new URL('../',import.meta.url);
const file=path=>new URL(path,root);
const official=JSON.parse(await readFile(file('xdr/fixtures/web-injection.json'),'utf8'));
const report=JSON.parse(await readFile(file('xdr/web-injection/result.json'),'utf8'));
const deny=JSON.parse(await readFile(file('xdr/temporary-deny.json'),'utf8'));
if(official.schema!=='aleph.xdr.fixture.v1'||official.moduleKey!=='web-injection'||!Array.isArray(official.alerts))
  throw new Error('Original training fixture is missing');
if(report.schema!=='aleph.xdr.result.v1'||report.moduleKey!=='web-injection'||
  !Array.isArray(report.decisions)||report.decisions.length!==official.alerts.length)
  throw new Error('Official runner result contract mismatch');
if(!Array.isArray(deny))throw new Error('Invalid temporary ZTNA rules');
const baseline=JSON.parse(await readFile(file('ztna/rules.json'),'utf8'));
if(!baseline||!Array.isArray(baseline.allow)||!Array.isArray(baseline.deny))
  throw new Error('Baseline policy missing');
const samples=official.alerts.map(item=>({
  id:item.id, timestamp:item.timestamp,
  rule:{level:item.rule.level,description:item.rule.description,mitre:item.rule.mitre},
  data:{srcip:item.data.srcip,srcuser:item.data.srcuser??'',
    url:item.data.url??'',count:item.data.count??null}
}));
const results=report.decisions.map((answer,i)=>({
  alertId:answer.alertId,action:answer.action,confidence:answer.confidence,reason:answer.reason,
  source:samples[i].data.srcip,description:samples[i].rule.description,
  level:samples[i].rule.level,attempts:samples[i].data.count??'–',
  normal:!samples[i].rule.mitre.includes('T1190') && samples[i].rule.level<=3
}));
const dashboard={scenario:'web-injection',schema:report.schema,
  generatedAt:'2026-10-12T05:00:00.000Z',fixtureCount:samples.length,
  counts:report.counts,normalBlocked:results.filter(x=>x.normal&&x.action==='block').length,
  temporaryDenyRules:deny.map(rule=>({id:rule.id,source:rule.source,alertId:rule.alertId,expiresAt:rule.expiresAt})),
  results};
await mkdir(file('public/'),{recursive:true});
await writeFile(file('public/report.json'),JSON.stringify(dashboard,null,2)+'\n');
await writeFile(file('public/samples.json'),JSON.stringify({alerts:samples},null,2)+'\n');
for(const name of ['index.html','app.js','styles.css'])
  await copyFile(file(name),file('public/'+name));
await copyFile(file('xdr/web-injection/decide.mjs'),file('public/decide.mjs'));
console.log(JSON.stringify({siteReady:true,total:samples.length,counts:report.counts,normalBlocked:dashboard.normalBlocked}));
