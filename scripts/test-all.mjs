import {spawnSync} from 'node:child_process';

function run(step,args) {
  console.log('\n[CHECK] '+step);
  const p=spawnSync(process.execPath,args,{encoding:'utf8',stdio:'inherit'});
  if(p.error)throw p.error;
  if(p.status!==0) {
    console.error('Failed at '+step+' (exit '+p.status+')');
    process.exit(p.status||1);
  }
}
run('XDR-02 Wazuh web-injection replay',['xdr/run.mjs','web-injection']);
run('XDR-02 original regression tests',['--test','tests/xdr-web-injection.test.mjs','tests/source-purity.test.mjs']);
run('XDR-03 original known-CVE replay',['xdr/run.mjs','known-cve']);
run('XDR-03 Log4Shell behavioral and policy tests',['--test','tests/xdr-known-cve.test.mjs']);
console.log('\n[PASS] XDR-02 and XDR-03 modules both verified separately');
