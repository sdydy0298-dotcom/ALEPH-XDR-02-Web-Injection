import {readFile,writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {runXdr} from '../scripts/xdr-run.mjs';
import {respond} from './web-injection/respond.mjs';
import {evaluateAccess} from '../ztna/evaluate.mjs';

if(process.argv[2]==='known-cve') {
  await import('./known-cve/run.mjs');
} else {
if(process.argv[2]!=='web-injection'){
  console.error('Usage: npm run xdr:run -- web-injection');
  process.exit(1);
}
const clock=new Date('2026-10-12T05:00:00.000Z');
const fixture=JSON.parse(await readFile(new URL('./fixtures/web-injection.json',import.meta.url),'utf8'));
const root=fileURLToPath(new URL('../',import.meta.url));
const report=await runXdr({root,moduleKey:'web-injection'});
const temp=new URL('./temporary-deny.json',import.meta.url);
const alertLog=new URL('./alerts.log',import.meta.url);
await writeFile(temp,'[]\n');
await writeFile(alertLog,'');
for(let i=0;i<fixture.alerts.length;i++){
  const alert=fixture.alerts[i], verdict=report.decisions[i];
  if(alert.id!==verdict.alertId)throw new Error('Alert order mismatch');
  await respond(alert,verdict,{now:clock,persist:true});
}
const rules=JSON.parse(await readFile(temp,'utf8'));
const logLines=(await readFile(alertLog,'utf8')).trim().split('\n').filter(Boolean);
const blockCount=report.counts.block,alertCount=report.counts.alert;
if(rules.length!==blockCount||logLines.length!==blockCount+alertCount)
  throw new Error('Saved response rules/logs do not match judge');
let normalBlocked=0;
for(let i=0;i<fixture.alerts.length;i++){
  const alert=fixture.alerts[i],decision=report.decisions[i];
  const access=await evaluateAccess(alert.data.srcip,clock.getTime());
  const baselineNormal=!(alert.rule?.mitre??[]).includes('T1190')&&Number(alert.rule?.level??0)<=3;
  if(baselineNormal&&(decision.action==='block'||access.action==='deny'))normalBlocked++;
  if(decision.action==='block'&&access.action!=='deny')throw new Error('Missing deny for '+alert.id);
  if(decision.action==='block'&&(await evaluateAccess(alert.data.srcip,clock.getTime()+16*60*1000)).action!=='allow')
    throw new Error('Expired rule still denies '+alert.id);
}
if(normalBlocked)throw new Error('Normal source denied');
console.log(JSON.stringify({schema:report.schema,counts:report.counts,normalBlocked,
  alertsLogged:logLines.length,temporaryDenyRules:rules.length,total:fixture.alerts.length}));

}
