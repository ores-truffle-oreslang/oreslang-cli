// Externally pinned Ed25519/DSSE digest signature verification.
// Never signs, imports a private key, grants merge authority or consumes replay state.
import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';

const TYPE='application/vnd.attolang.live-merge-evidence-sha256.v1';
const HEX=/^[a-f0-9]{64}$/;
const base64 = s => {
  if (typeof s !== 'string' || s.length === 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(s)) return null;
  const decoded=Buffer.from(s,'base64');
  return decoded.toString('base64')===s ? decoded : null;
};
export function pae(type,payload) {
  const prefix=Buffer.from('DSSEv1 '+Buffer.byteLength(type)+' '+type+' '+payload.length+' ','utf8');
  return Buffer.concat([prefix,payload]);
}
export function verifyExternalSignature(candidateSha256,envelope,anchor) {
  const errors=[];
  const deny=x=>errors.push(x);
  if (typeof candidateSha256 !== 'string' || !HEX.test(candidateSha256)) deny('CANDIDATE_SHA_INVALID');
  if (!envelope || typeof envelope!=='object' || Array.isArray(envelope) ||
      envelope.payloadType!==TYPE || !Array.isArray(envelope.signatures) ||
      envelope.signatures.length!==1 ||
      Object.keys(envelope).sort().join(',') !== 'payload,payloadType,signatures') deny('DSSE_ENVELOPE_INVALID');
  if (!anchor || typeof anchor!=='object' || Array.isArray(anchor) ||
      typeof anchor.spki_pem !== 'string' || typeof anchor.keyid !== 'string' ||
      anchor.revoked !== false) deny('EXTERNAL_TRUST_ANCHOR_MISSING_OR_REVOKED');
  const payload=base64(envelope?.payload);
  const signature=base64(envelope?.signatures?.[0]?.sig);
  const sid=envelope?.signatures?.[0]?.keyid;
  if (!payload || payload.toString('utf8')!==candidateSha256+'\n') deny('DSSE_PAYLOAD_UNBOUND');
  if (!signature || signature.length!==64 || typeof sid!=='string') deny('DSSE_SIGNATURE_INVALID');
  if (errors.length===0) {
    try {
      const key=createPublicKey(anchor.spki_pem);
      const der=key.export({type:'spki',format:'der'});
      const expected='sha256:'+createHash('sha256').update(der).digest('hex');
      if (key.asymmetricKeyType!=='ed25519' || anchor.keyid!==expected || sid!==expected) {
        deny('EXTERNAL_SIGNER_IDENTITY_MISMATCH');
      } else if (!verifySignature(null,pae(TYPE,payload),key,signature)) {
        deny('BAD_EXTERNAL_SIGNATURE');
      }
    } catch {
      deny('EXTERNAL_KEY_INVALID');
    }
  }
  return {
    signature_valid:errors.length===0,
    reasons:errors,
    // Validity proves ONLY signature over a hash under the *supplied* trust root.
    // Reviewer independence, provenance, trust-anchor protection, clock, and
    // durable anti-replay CAS are external to this source-controlled model.
    merge_authorized:false,
    release_authorized:false,
    private_source_export_authorized:false
  };
}
export const ATTESTATION_PAYLOAD_TYPE=TYPE;
