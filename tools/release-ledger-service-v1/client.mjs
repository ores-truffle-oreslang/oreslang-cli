import { randomBytes } from 'node:crypto';
import { canonical, macFor, normalizeSecret } from './protocol.mjs';

// The HMAC key is a test/service credential, not a delegated release signing key.
export function signedLocalRequest({secret,client,body,path='/v1/claim',
  timestamp=Math.floor(Date.now()/1000),nonce=randomBytes(32).toString('hex')}){
  normalizeSecret(secret);
  const raw=canonical(body);
  const mac=macFor({secret,method:'POST',path,client,timestamp,nonce,body:raw});
  return {method:'POST',path,raw:Buffer.from(raw),headers:{
    'content-type':'application/json','x-atto-client':client,
    'x-atto-time':String(timestamp),'x-atto-nonce':nonce,'x-atto-mac':mac
  }};
}
