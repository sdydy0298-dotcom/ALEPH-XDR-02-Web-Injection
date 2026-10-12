// MITRE ATT&CK T1190. This is a fully standalone, deterministic judge module.
// PATTERNS are mirrored from patterns.json. No imports, I/O, fetch or shared state.
const PATTERNS = Object.freeze({
  sql:'T1190-SQL-Query-Injection',
  script:'T1190-Script-Injection',
  path:'T1190-Path-Traversal',
  command:'T1190-Command-Separator',
  mixed:'T1190-Mixed-Injection',
  uncertain:'T1190-Uncertain-Web-Request'
});
const object = x => x && typeof x==='object' && !Array.isArray(x) ? x : {};
const first = (...xs) => xs.find(x => x!==undefined && x!==null && x!=='') ?? null;
const string = x => typeof x==='string' ? x : '';
const number = x => {
  if(typeof x==='number' && Number.isFinite(x) && x>=0 && x<=1000000) return x;
  if(typeof x==='string' && /^\s*\d+(?:\.\d+)?\s*$/.test(x)) {
    const n=Number(x);
    return n<=1000000?n:null;
  }
  return null;
};
const ipOk = x => {
  if(typeof x!=='string')return false;
  const addr=x.trim();
  if(/^(?:\d{1,3}\.){3}\d{1,3}$/.test(addr))
    return addr.split('.').every(segment=>Number(segment)>=0&&Number(segment)<=255);
  return /^[0-9a-f:]{2,45}$/i.test(addr) && addr.includes(':');
};
function unpackUrl(raw) {
  let text=string(raw).slice(0,5000).replace(/\+/g,' ');
  for(let i=0;i<2;i++){
    try {const next=decodeURIComponent(text);if(next===text)break;text=next;}catch {break;}
  }
  return text.toLowerCase();
}
function indicators(desc,query) {
  const sql=/\bunion\s+(?:all\s+)?select\b|\binformation_schema\b|\b(?:sleep|pg_sleep|benchmark)\s*\(|\bwaitfor\s+delay\b|(?:['"]\s*(?:or|and)\s+['"]?\w+['"]?\s*=\s*['"]?\w+)|;\s*(?:select|insert|update|drop|delete|exec)\b/i.test(query)
    || /(?:sql\s*(?:구문|표식|주입)|데이터베이스\s*조회.{0,25}이어\s*붙)/i.test(desc);
  const script=/<\s*script\b|on(?:error|load)\s*=|javascript\s*:/i.test(query)
    || /스크립트\s*(?:삽입|표식)/.test(desc);
  const path=/(?:\.\.[\\/])+/.test(query)
    || /경로.{0,25}(?:거슬러|이탈)/.test(desc);
  const command=/(?:;|&&|\|\|)\s*(?:id|whoami|cat|curl|wget|bash|sh|powershell|cmd|rm)\b/i.test(query)
    || /명령\s*구분자/.test(desc);
  return {sql,script,path,command};
}
function describe(alert) {
  const a=object(alert), d=object(a.data), r=object(a.rule), req=object(a.request), nested=object(d.request);
  const description=[string(r.description),string(a.description),string(d.description)].filter(Boolean).join(' ').toLowerCase();
  const raw=[d.url,d.uri,d.path,d.query,d.request,d.request_url,d.request_uri,d.payload,
    req.url,req.path,req.query,nested.url,nested.uri,a.url,a.uri,a.path,a.query,
    a.full_log,d.full_log].filter(v=>typeof v==='string').join(' ');
  const query=unpackUrl(raw);
  const count=number(first(d.count,d.request_count,d.repeat_count,d.hits,d.frequency,
    a.count,a.request_count,a.repeat_count,r.frequency,r.count));
  const level=number(first(r.level,a.level,d.level)) ?? 0;
  const mitre=Array.isArray(r.mitre) && r.mitre.some(x=>x==='T1190'||(x&&typeof x==='object'&&x.id==='T1190'));
  const source=first(d.srcip,d.src_ip,d.source_ip,d.client_ip,a.srcip,a.source_ip,a.client_ip);
  const signals=indicators(description,query);
  const active=Object.keys(signals).filter(k=>signals[k]);
  const pattern=active.length>1 ? PATTERNS.mixed : active.length===1 ? PATTERNS[active[0]] : PATTERNS.uncertain;
  const noisy=/반복|연속|여러\s*번|같은\s*주소|이어\s*붙|번갈아|다수|repeated|multiple|consecutive/i.test(description);
  return {description,count,level,mitre,sourceOk:ipOk(source),signals,active,pattern,noisy};
}
export function decide(alert) {
  const e=describe(alert);
  const score=(confidence,reason)=>({
    action:confidence>=0.85?'block':confidence>=0.5?'alert':'record',
    confidence, reason
  });
  const repeated=e.count!==null&&e.count>=8;
  const clear=e.active.length>0 && repeated && e.level>=10 && e.sourceOk &&
    (e.mitre || e.noisy);
  if(clear)return score(e.active.length>1?0.98:0.96,e.pattern);
  // An attack payload in a single request is suspicious, not enough to deny a source IP.
  if(e.active.length>0)return score(e.mitre?0.73:0.66,e.pattern);
  // ATT&CK-tagged Wazuh alerts can be weak or ambiguous even when a keyword
  // looks like an ordinary course title; keep them as review-only alerts.
  if(e.mitre && e.level>=5)return score(0.57,PATTERNS.uncertain);
  return score(0.08,'T1190: 정상 웹 요청');
}
