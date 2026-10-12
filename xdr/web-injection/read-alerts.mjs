import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {isIP} from 'node:net';

const input=new URL('../fixtures/web-injection.json',import.meta.url);
function redact(value) {
  return String(value??'').replace(/[\r\n\t]/g,' ')
    .replace(/\b(?:password|passwd|pwd|token|secret|cookie|authorization|api[_-]?key)\b\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s&,;]+)/gi,'[REDACTED]')
    .replace(/\bBearer\s+\S+/gi,'Bearer [REDACTED]')
    .replace(/\b[A-Za-z0-9_-]{48,}\b/g,'[REDACTED]').slice(0,220);
}
export function projectAlert(alert) {
  const data=alert?.data ?? {};
  const raw=String(data.srcip??data.src_ip??data.source_ip??alert?.srcip??alert?.source_ip??'');
  const level=Number(alert?.rule?.level??0);
  return {
    time:redact(alert?.timestamp),
    source:isIP(raw)?raw:'',
    account:redact(data.srcuser??data.dstuser??data.username??alert?.account??''),
    level:Number.isFinite(level)?level:0,
    description:redact(alert?.rule?.description)
  };
}
export async function readAlerts() {
  const object=JSON.parse(await readFile(input,'utf8'));
  const alerts=Array.isArray(object)?object:object?.alerts;
  if(!Array.isArray(alerts))throw new Error('Invalid XDR fixture');
  return alerts.map(projectAlert);
}
if(process.argv[1] && import.meta.url===pathToFileURL(resolve(process.argv[1])).href) {
  for(const item of await readAlerts())console.log(JSON.stringify(item));
}
