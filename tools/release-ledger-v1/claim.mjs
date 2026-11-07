#!/usr/bin/env node
// Public source-free CAS probe for native concurrency and crash recovery tests.
// No path returns successful release exit 0.
import { bootstrapLocalLedger, readLocalLedger, consumeLocalAdvisoryClaim } from './sqlite-ledger.mjs';
const deny=(reason)=>({classification:'DENIED',reason,ledger_cas_committed:false,release_authorized:false});
try {
  if(process.argv.length!==5 || !['bootstrap','read','consume'].includes(process.argv[3]))
    throw Error('usage: node claim.mjs ABSOLUTE_DB_PATH bootstrap|read|consume BASE64_JSON');
  const file=process.argv[2];
  const input=JSON.parse(Buffer.from(process.argv[4],'base64').toString('utf8'));
  let answer;
  if(process.argv[3]==='bootstrap')answer=bootstrapLocalLedger(file,input.ledger_id);
  else if(process.argv[3]==='read')answer=readLocalLedger(file,input.ledger_id);
  else answer=consumeLocalAdvisoryClaim(file,input.pin,input.claim,
    phase=>{if(phase===process.env.ATTO_LEDGER_TEST_FAULT)process.exit(86);});
  process.stdout.write(JSON.stringify(answer)+'\n');
  process.exitCode=answer.classification==='DENIED'?1:3;
}catch(e){
  process.stderr.write(JSON.stringify(deny('CLI_INPUT_DENIED: '+e.message))+'\n');
  process.exitCode=2;
}
