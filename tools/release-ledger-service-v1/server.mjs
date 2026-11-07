import http from 'node:http';
import { checkAuth, deny, local, normalizeSecret } from './protocol.mjs';
import { commitPgClaim, readPgReceipt } from './postgres.mjs';

function response(res,status,body) {
  res.writeHead(status,{'content-type':'application/json; charset=utf-8',
    'cache-control':'no-store','x-content-type-options':'nosniff',
    'content-security-policy':"default-src 'none'"});
  res.end(JSON.stringify(body)+'\n');
}
function authFailure(res,checked) {
  response(res,checked.status||403,deny('REQUEST_NOT_ADMITTED',403));
}
export function createLedgerHttpService({pool,secret,expectedClient,
  nowSeconds=()=>Math.floor(Date.now()/1000)}) {
  normalizeSecret(secret);
  if(typeof expectedClient!=='string'||!/^[a-z][a-z0-9._-]{2,63}$/.test(expectedClient))
    throw Error('INVALID_AUTH_CLIENT');
  if(!pool||typeof pool.connect!=='function'||typeof pool.query!=='function')
    throw Error('INVALID_POOL');
  const server=http.createServer(async(req,res)=>{
    try{
      if(req.method==='GET'&&req.url==='/healthz'){
        response(res,200,local('SERVICE_ALIVE_NOT_A_RELEASE_AUTHORITY',{
          ledger_cas_committed:false,release_publisher_enabled:false}));
        return;
      }
      if(req.method!=='POST'||!['/v1/claim','/v1/receipt'].includes(req.url)){
        response(res,404,deny('UNKNOWN_ROUTE',404));return;
      }
      if(req.headers['content-type']!=='application/json'){
        response(res,415,deny('INVALID_CONTENT_TYPE',415));return;
      }
      let length=0;
      const chunks=[];
      for await(const chunk of req){
        length+=chunk.length;
        if(length>32768){
          response(res,413,deny('BODY_TOO_LARGE',413));return;
        }
        chunks.push(chunk);
      }
      const checked=checkAuth({headers:req.headers,rawHeaders:req.rawHeaders,
        method:req.method,path:req.url,rawBody:Buffer.concat(chunks),
        secret,expectedClient,nowSeconds:nowSeconds()});
      if(!checked.ok){authFailure(res,checked);return;}
      if(req.url==='/v1/receipt'){
        const v=await readPgReceipt(pool,checked.client,checked.body.client_request_id);
        response(res,v.classification==='DENIED'?v.status||404:200,v);
        return;
      }
      const v=await commitPgClaim(pool,{client:checked.client,
        authNonce:checked.nonce,bodyDigest:checked.bodyDigest,
        claim:checked.body});
      // COMMIT_UNVERIFIED is deliberately not an OK/denied HTTP response.
      const status=v.classification==='DENIED'?(v.status||409):
        v.classification==='LOCAL_PG_COMMIT_UNVERIFIED'?503:200;
      response(res,status,v);
    }catch(e){
      response(res,503,local('SERVICE_ERROR_UNVERIFIED',{
        ledger_cas_committed:null,requires_manual_reconciliation:true,
        reason:'OPERATION_DID_NOT_PRODUCE_VERIFIABLE_RESPONSE'}));
    }
  });
  server.requestTimeout=15000;
  server.headersTimeout=16000;
  server.keepAliveTimeout=1500;
  server.maxHeadersCount=32;
  return server;
}
// Direct invocation binds loopback only. No production deployment or release
// publisher is installed; schema must be provisioned out of band.
if(process.argv[1]&&import.meta.url===new URL('file://'+process.argv[1]).href){
  const url=process.env.ATTO_LEDGER_PG_URL;
  const secret=process.env.ATTO_LEDGER_HMAC_KEY_HEX;
  const expectedClient=process.env.ATTO_LEDGER_TEST_CLIENT;
  if(!url||!secret||!expectedClient)throw Error('LEDGER_CONFIG_MISSING');
  const {default:pg}=await import('pg');
  const pool=new pg.Pool({connectionString:url,max:12,
    connectionTimeoutMillis:3000,idleTimeoutMillis:5000});
  const srv=createLedgerHttpService({pool,secret,expectedClient});
  const port=Number(process.env.ATTO_LEDGER_PORT||'8788');
  if(!Number.isSafeInteger(port)||port<1024||port>65535)
    throw Error('INVALID_LOOPBACK_PORT');
  srv.listen(port,'127.0.0.1',()=>console.log('LOCAL_DIAGNOSTIC_ONLY'));
  const stop=async()=>{srv.close();await pool.end();};
  process.once('SIGINT',stop);process.once('SIGTERM',stop);
}
