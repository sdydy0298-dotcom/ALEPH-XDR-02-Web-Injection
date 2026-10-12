import {readFile,writeFile,appendFile,mkdir} from 'node:fs/promises';
import {isIP} from 'node:net';
import {dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {decide} from './decide.mjs';
import {checkAccess} from '../../ztna/check.mjs';
const denyFile=new URL('../temporary-deny.json',import.meta.url);
const logFile=new URL('../alerts.log',import.meta.url);
const idOf=value=>/^[a-zA-Z0-9_.:-]{1,90}$/.test(String(value??''))?String(value):null;
const ipOf=value=>typeof value==='string'&&isIP(value.trim())?value.trim():null;
async function existingRules() {
  try {
    const result=JSON.parse(await readFile(denyFile,'utf8'));
    if(!Array.isArray(result))throw new Error('Invalid deny list');
    return result;
  }catch(error){if(error.code==='ENOENT')return [];throw error;}
}
export async function respond(alert,decision,{now=new Date(),persist=true}={}) {
  if(!decision||!['block','alert','record'].includes(decision.action)||
    !Number.isFinite(decision.confidence)||decision.confidence<0||decision.confidence>1)
    throw new TypeError('Invalid XDR verdict');
  if(!(now instanceof Date)||Number.isNaN(now.getTime()))throw new TypeError('Invalid clock');
  const d=alert?.data??{};
  const source=ipOf(d.srcip??d.src_ip??d.source_ip??d.client_ip??alert?.srcip??alert?.source_ip);
  const alertId=idOf(alert?.id??alert?.alertId);
  const active=(persist?await existingRules():[]).filter(rule=>
    rule?.action==='deny' && Number.isFinite(Date.parse(rule.expiresAt)) &&
    Date.parse(rule.expiresAt)>now.getTime());
  const verified=decide(alert);
  // Never accept a forged block result. The pure judge must independently agree.
  if(decision.action==='block' && decision.confidence>=0.85 &&
    verified.action==='block' && source && alertId) {
    const rule={id:'xdr-'+alertId,action:'deny',source,alertId,
      reason:verified.reason,createdAt:now.toISOString(),
      expiresAt:new Date(now.getTime()+15*60*1000).toISOString()};
    if(!active.some(item=>item.id===rule.id))active.push(rule);
  }
  const notification={alertId:alertId??'unknown',action:decision.action,
    confidence:decision.confidence,reason:verified.reason,at:now.toISOString()};
  if(persist){
    await mkdir(dirname(fileURLToPath(denyFile)),{recursive:true});
    await writeFile(denyFile,JSON.stringify(active,null,2)+'\n');
    if(decision.action!=='record')await appendFile(logFile,JSON.stringify(notification)+'\n');
  }
  return {notification:decision.action==='record'?null:notification,
    rules:active,access:source?checkAccess(source,active,now.getTime()):
      {action:'allow',reason:'No valid source address'}};
}
