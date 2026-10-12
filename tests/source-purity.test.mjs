import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
test('official runner and standalone judge are copied without runtime dependencies',async()=>{
  const packageData=JSON.parse(await readFile(new URL('../package.json',import.meta.url),'utf8'));
  assert.equal(packageData.scripts['xdr:run'],'node xdr/run.mjs');
  const judge=await readFile(new URL('../xdr/web-injection/decide.mjs',import.meta.url),'utf8');
  const original=await readFile(new URL('../scripts/xdr-run.mjs',import.meta.url),'utf8');
  assert.match(judge,/export function decide\(alert\)/);
  assert.doesNotMatch(judge,/\bimport\s*\(/);
  assert.doesNotMatch(original,/from ['"]node:(?:http|https|net|dns)['"]|\bfetch\(/);
});
test('pattern list has one-line MITRE T1190 evidence for each rule',async()=>{
 const patterns=JSON.parse(await readFile(new URL('../xdr/web-injection/patterns.json',import.meta.url),'utf8'));
 const code=await readFile(new URL('../xdr/web-injection/decide.mjs',import.meta.url),'utf8');
 assert.ok(patterns.length>=3);
 for(const pattern of patterns){
   assert.ok(pattern.name && pattern.condition && pattern.evidence);
   assert.match(pattern.evidence,/T1190/);
   assert.doesNotMatch(pattern.evidence,/[\n\r]/);
   assert.ok(code.includes(pattern.name));
 }
});
