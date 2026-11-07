import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

const LEDGER=/^[a-z][a-z0-9._-]{2,63}$/;
const REPO=/^ores-truffle-oreslang\/[a-z0-9][a-z0-9._-]{0,119}$/;
const H40=/^[0-9a-f]{40}$/, H64=/^[0-9a-f]{64}$/;
const CLIENT=/^[a-z][a-z0-9._-]{2,63}$/;
const MAX_BODY=32768;
const ZERO='0'.repeat(64);
export const MAX_SKEW_SECONDS=30;
export const MAX_SEQUENCE=1000000;
export const hash=v=>createHash('sha256').update(v).digest('hex');
export const isRecord=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
export const hex64=v=>typeof v==='string'&&H64.test(v);
export const validClient=v=>typeof v==='string'&&CLIENT.test(v);
export const validLedger=v=>typeof v==='string'&&LEDGER.test(v);
export const validRepo=v=>typeof v==='string'&&REPO.test(v);
export const safeInt=v=>Number.isSafeInteger(v)&&v>=0&&v<=MAX_SEQUENCE;
export const posInt=v=>Number.isSafeInteger(v)&&v>0&&v<=MAX_SEQUENCE;
export const canonical=value=>{
  if(value===null)return 'null';
  if(typeof value==='string')return JSON.stringify(value);
  if(typeof value==='number') {
    if(!Number.isSafeInteger(value)||Object.is(value,-0))throw Error('NONINTEGER_JSON');
    return String(value);
  }
  if(value===true)return 'true';
  if(value===false)return 'false';
  if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
  if(!isRecord(value))throw Error('UNSUPPORTED_JSON');
  const names=Object.keys(value).sort();
  return '{'+names.map(name=>JSON.stringify(name)+':'+canonical(value[name])).join(',')+'}';
};
export const exact=(v,fields)=>isRecord(v)&&Object.keys(v).length===fields.length&&
  fields.every(k=>Object.hasOwn(v,k));
const claimFields=['artifact_sha256','client_request_id','head_sha','intent_sha256',
  'ledger_id','nonce','policy_sequence','previous_intent_sha256',
  'repository','sequence'];
export const validClaim=v=>exact(v,claimFields)&&validLedger(v.ledger_id)&&
  validRepo(v.repository)&&posInt(v.sequence)&&posInt(v.policy_sequence)&&
  hex64(v.previous_intent_sha256)&&hex64(v.intent_sha256)&&v.intent_sha256!==ZERO&&
  hex64(v.nonce)&&v.nonce!==ZERO&&hex64(v.artifact_sha256)&&
  hex64(v.client_request_id)&&typeof v.head_sha==='string'&&H40.test(v.head_sha)&&
  (v.sequence!==1||v.previous_intent_sha256===ZERO);
export const validBootstrap=v=>exact(v,['ledger_id','repository'])&&
  validLedger(v.ledger_id)&&validRepo(v.repository);
export const validReceiptRequest=v=>exact(v,['client_request_id'])&&hex64(v.client_request_id);
export const normalizeSecret=key=>{
  if(typeof key!=='string'||!/^[0-9a-f]{64}$/.test(key))
    throw Error('INVALID_SERVICE_HMAC_KEY');
  return Buffer.from(key,'hex');
};
export const deny=(reason,status=403)=>({classification:'DENIED',
  reason,status,ledger_cas_committed:false,release_authorized:false,
  authenticated_github:false,compiler_guest_parity_proven:false});
export const local=(classification,fields={})=>({classification,...fields,
  release_authorized:false,authenticated_github:false,compiler_guest_parity_proven:false});
const reqLine=(method,path,client,ts,nonce,bodyDigest)=>[
  'ATTO-LEDGER-SERVICE-v1',method,path,client,ts,nonce,bodyDigest
].join('\n')+'\n';
export const macFor=({secret,method,path,client,timestamp,nonce,body})=>{
  const k=Buffer.isBuffer(secret)?secret:normalizeSecret(secret);
  if(k.length!==32||!['POST'].includes(method)||!['/v1/claim','/v1/receipt'].includes(path)||
    !validClient(client)||!Number.isSafeInteger(timestamp)||timestamp<=0||
    !hex64(nonce)||nonce===ZERO||typeof body!=='string')
    throw Error('INVALID_SIGNING_INPUT');
  return createHmac('sha256',k).update(reqLine(method,path,client,
    String(timestamp),nonce,hash(Buffer.from(body,'utf8')))).digest('hex');
};
export function parseBody(input){
  if(!Buffer.isBuffer(input)||input.length<2||input.length>MAX_BODY)
    throw Error('MISSING_OR_OVERSIZE_BODY');
  const value=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(input);
  const parsed=JSON.parse(value);
  if(!isRecord(parsed)||canonical(parsed)!==value)throw Error('NONCANONICAL_BODY');
  return parsed;
}
export function checkAuth({headers,rawHeaders,method,path,rawBody,secret,
  expectedClient,nowSeconds}){
  try {
    if(!Buffer.isBuffer(rawBody))throw Error('MISSING_BODY');
    const body=parseBody(rawBody);
    if(!['/v1/claim','/v1/receipt'].includes(path)||method!=='POST')
      throw Error('UNKNOWN_ROUTE');
    const map=new Map();
    for(let i=0;i<rawHeaders.length;i+=2){
      const key=String(rawHeaders[i]).toLowerCase();
      if(key.startsWith('x-atto-')){
        if(map.has(key))throw Error('DUPLICATE_AUTH_HEADER');
        map.set(key,String(rawHeaders[i+1]));
      }
    }
    const allowed=['x-atto-client','x-atto-time','x-atto-nonce','x-atto-mac'];
    if(map.size!==4||![...map.keys()].every(k=>allowed.includes(k)))
      throw Error('MISSING_OR_UNKNOWN_AUTH_HEADER');
    const client=map.get('x-atto-client');
    const ts=map.get('x-atto-time');
    const nonce=map.get('x-atto-nonce');
    const mac=map.get('x-atto-mac');
    if(!validClient(client)||client!==expectedClient||
      !/^[1-9][0-9]{0,11}$/.test(ts)||!hex64(nonce)||nonce===ZERO||!hex64(mac))
      throw Error('INVALID_CLIENT_OR_NONCE');
    const timestamp=Number(ts);
    if(!Number.isSafeInteger(timestamp)||!Number.isSafeInteger(nowSeconds)||
      Math.abs(timestamp-nowSeconds)>MAX_SKEW_SECONDS)
      throw Error('STALE_OR_FUTURE_REQUEST');
    const expected=macFor({secret,method,path,client,timestamp,nonce,
      body:rawBody.toString('utf8')});
    if(!timingSafeEqual(Buffer.from(mac,'hex'),Buffer.from(expected,'hex')))
      throw Error('INVALID_REQUEST_MAC');
    if(!validClaim(body)&&path==='/v1/claim')
      throw Error('INVALID_CLAIM_BODY');
    if(!validReceiptRequest(body)&&path==='/v1/receipt')
      throw Error('INVALID_RECEIPT_BODY');
    return {ok:true,client,nonce,timestamp,body,bodyDigest:hash(rawBody)};
  }catch(e){return {ok:false,...deny('AUTH_OR_INPUT_DENIED: '+e.message)};}
}
export const ZERO_DIGEST=ZERO;
