// Non-authorizing, loopback-only signed-claim diagnostic HTTP surface.
// Independent HMAC domain: v1 client credentials cannot authorize v2 routes.
import http from 'node:http';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { canonical, normalizeSecret, parseBody, hash, hex64, validClient, deny,
  local, exact } from '../release-ledger-service-v1/protocol.mjs';
import { readPgReceipt } from '../release-ledger-service-v1/postgres.mjs';
import { pinOperatorEvidence, consumeVerifiedSignedServiceRequest } from './signed-claim.mjs';

const CLAIM='/v2/signed-claim', RECEIPT='/v2/receipt', DOMAIN='ATTO-SIGNED-LEDGER-v2';
function mac(secret,method,path,client,ts,nonce,digest){
  if(method!=='POST'||![CLAIM,RECEIPT].includes(path)||!validClient(client)||
     !Number.isSafeInteger(ts)||ts<=0||!hex64(nonce)||
     nonce==='0'.repeat(64)||!hex64(digest))
    throw Error('INVALID_DOMAIN_SIGNING_PARAMETERS');
  return createHmac('sha256',normalizeSecret(secret)).update([
    DOMAIN,method,path,client,String(ts),nonce,digest
  ].join('\n')+'\n').digest('hex');
}
export function signV2DiagnosticRequest({secret,client,body,path=CLAIM,
  timestamp=Math.floor(Date.now()/1000),nonce=randomBytes(32).toString('hex')}){
  const raw=Buffer.from(canonical(body));
  const tag=mac(secret,'POST',path,client,timestamp,nonce,hash(raw));
  return {method:'POST',path,body:raw,headers:{
    'content-type':'application/json','x-atto-client':client,
    'x-atto-time':String(timestamp),'x-atto-nonce':nonce,'x-atto-mac':tag
  }};
}
export function verifyV2DiagnosticAuth({secret,expectedClient,method,path,
  rawHeaders,rawBody,nowSeconds}){
  try{
    if(!Buffer.isBuffer(rawBody))throw Error('MISSING_RAW_BYTES');
    const body=parseBody(rawBody);
    if(method!=='POST'||![CLAIM,RECEIPT].includes(path))throw Error('UNKNOWN_ROUTE');
    if(!Array.isArray(rawHeaders)||rawHeaders.length%2!==0)
      throw Error('INVALID_HTTP_HEADERS');
    const fields=new Map();
    for(let i=0;i<rawHeaders.length;i+=2){
      const k=String(rawHeaders[i]).toLowerCase();
      if(k.startsWith('x-atto-')){
        if(fields.has(k))throw Error('DUPLICATE_AUTH_HEADER');
        fields.set(k,String(rawHeaders[i+1]));
      }
    }
    const REQUIRED=['x-atto-client','x-atto-time','x-atto-nonce','x-atto-mac'];
    if(fields.size!==4||![...fields.keys()].every(k=>REQUIRED.includes(k)))
      throw Error('MISSING_OR_EXTRA_AUTHORITY_HEADER');
    const client=fields.get('x-atto-client'),time=fields.get('x-atto-time');
    const nonce=fields.get('x-atto-nonce'),sig=fields.get('x-atto-mac');
    if(client!==expectedClient||!validClient(client)||
       !/^[1-9][0-9]{0,11}$/.test(time)||!hex64(nonce)||
       !hex64(sig)||nonce==='0'.repeat(64))
      throw Error('INVALID_CLIENT_TIMESTAMP_OR_NONCE');
    const ts=Number(time);
    if(!Number.isSafeInteger(nowSeconds)||Math.abs(nowSeconds-ts)>30)
      throw Error('UNTRUSTED_LOCAL_CLOCK_WINDOW');
    const actual=mac(secret,method,path,client,ts,nonce,hash(rawBody));
    if(!timingSafeEqual(Buffer.from(sig,'hex'),Buffer.from(actual,'hex')))
      throw Error('BAD_REQUEST_MAC');
    if(path===RECEIPT&&!exact(body,['client_request_id']))
      throw Error('INVALID_RECEIPT_REQUEST_FIELDS');
    if(path===RECEIPT&&!hex64(body.client_request_id))
      throw Error('INVALID_RECEIPT_IDENTIFIER');
    return {ok:true,body,client,nonce,digest:hash(rawBody)};
  }catch(e){return {ok:false,...deny('SIGNED_AUTH_DENIED: '+e.message)};}
}
function send(res,status,payload){
  res.writeHead(status,{
    'content-type':'application/json; charset=utf-8',
    'cache-control':'no-store','x-content-type-options':'nosniff',
    'content-security-policy':"default-src 'none'"
  });
  res.end(JSON.stringify(payload)+'\n');
}
export function createSignedDiagnosticHttpService({pool,secret,expectedClient,
  operatorPin,nowSeconds=()=>Math.floor(Date.now()/1000),
  nowUtc=()=>new Date().toISOString().slice(0,19)+'Z'}){
  normalizeSecret(secret);
  if(!validClient(expectedClient)||!pool||typeof pool.connect!=='function'||
     typeof pool.query!=='function')
    throw Error('INVALID_SIGNED_HTTP_CONFIGURATION');
  const pinned=pinOperatorEvidence(operatorPin);
  const server=http.createServer(async(req,res)=>{
    try{
      if(req.method==='GET'&&req.url==='/healthz'){
        send(res,200,local('NONPUBLISHING_SIGNED_DIAGNOSTIC_ALIVE',{
          ledger_cas_committed:false,release_publisher_enabled:false}));
        return;
      }
      if(req.method!=='POST'||![CLAIM,RECEIPT].includes(req.url)){
        send(res,404,deny('UNKNOWN_SIGNED_ROUTE',404));return;
      }
      if(req.headers['content-type']!=='application/json'){
        send(res,415,deny('UNSUPPORTED_MEDIA_TYPE',415));return;
      }
      let n=0;const chunks=[];
      for await(const part of req){
        n+=part.length;
        if(n>32768){send(res,413,deny('SIGNED_BODY_OVERSIZE',413));return;}
        chunks.push(part);
      }
      const checked=verifyV2DiagnosticAuth({
        secret,expectedClient,method:req.method,path:req.url,
        rawHeaders:req.rawHeaders,rawBody:Buffer.concat(chunks),nowSeconds:nowSeconds()
      });
      if(!checked.ok){
        send(res,403,deny('SIGNED_REQUEST_NOT_ADMITTED'));return;
      }
      if(req.url===RECEIPT){
        const v=await readPgReceipt(pool,checked.client,checked.body.client_request_id);
        send(res,v.classification==='DENIED'?(v.status||404):200,v);return;
      }
      const v=await consumeVerifiedSignedServiceRequest({
        pool,client:checked.client,authNonce:checked.nonce,
        bodyDigest:checked.digest,body:checked.body,
        operatorPin:pinned,now:nowUtc()
      });
      const status=v.classification==='DENIED'?(v.status||403):
        (v.ledger_cas_committed===null?503:200);
      send(res,status,v);
    }catch{
      send(res,503,local('SIGNED_SERVICE_OUTCOME_UNVERIFIED',{
        ledger_cas_committed:null,requires_manual_reconciliation:true}));
    }
  });
  server.requestTimeout=15000;
  server.headersTimeout=16000;
  server.keepAliveTimeout=1500;
  server.maxHeadersCount=32;
  return server;
}
