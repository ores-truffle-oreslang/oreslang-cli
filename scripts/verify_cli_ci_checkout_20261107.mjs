#!/usr/bin/env node
// Immutable, read-only source admission. Not an authenticated external merge authority.
import { createHash } from 'node:crypto';
import { lstatSync, fstatSync, openSync, closeSync, readFileSync, readdirSync, realpathSync, constants } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const SHA=/^[a-f0-9]{40}$/;
const MAX_PATHS=10000;
const MAX_BLOB_BYTES=64*1024*1024;
const MAX_GIT_OUTPUT=4*1024*1024;
const asciiPath=/^[^\x00-\x1f\x7f]+$/u;
function deny(reason){ throw new Error('EXACT_PHYSICAL_SOURCE_DENIED:'+reason); }
function blobHash(data){return createHash('sha1').update(Buffer.from('blob '+data.length+'\0')).update(data).digest('hex');}
function git(args,root,gitBin){
  const env={ PATH:'/usr/bin:/bin', HOME:process.env.HOME||'/tmp', LANG:'C', LC_ALL:'C',
    GIT_CONFIG_NOSYSTEM:'1', GIT_NO_REPLACE_OBJECTS:'1', GIT_OPTIONAL_LOCKS:'0' };
  const out=spawnSync(gitBin,['-c','core.fsmonitor=false','-c','core.untrackedCache=false','-c','core.ignorecase=false',...args],{
    cwd:root,env,encoding:null,maxBuffer:MAX_GIT_OUTPUT,timeout:8000,windowsHide:true
  });
  if(out.error||out.status!==0)deny('GIT_COMMAND_FAILED');
  return out.stdout;
}
export function verifyCheckout({root=process.cwd(),expected=process.env.EXPECTED_HEAD,environment=process.env,gitBin='/usr/bin/git'}={}){
  if(typeof expected!=='string'||!SHA.test(expected))deny('EXPECTED_HEAD_INVALID');
  if(!isAbsolute(root)||realpathSync(root)!==resolve(root))deny('NONCANONICAL_ROOT');
  for(const key of Object.keys(environment))if(key.startsWith('GIT_'))deny('INHERITED_GIT_CONTROL');
  const gitControl=lstatSync(join(root,'.git'));
  if(!gitControl.isDirectory()||gitControl.isSymbolicLink())deny('UNSAFE_GIT_DIRECTORY');
  const top=git(['rev-parse','--show-toplevel'],root,gitBin).toString('utf8').trim();
  if(top!==root)deny('WRONG_CHECKOUT_ROOT');
  const head=git(['rev-parse','--verify','HEAD^{commit}'],root,gitBin).toString('utf8').trim();
  if(head!==expected)deny('HEAD_CHANGED');
  const tree=git(['rev-parse','--verify','HEAD^{tree}'],root,gitBin).toString('utf8').trim();
  if(!SHA.test(tree))deny('BAD_TREE_SHA');

  const index=git(['ls-files','-v','-z'],root,gitBin);
  const flags=index.toString('utf8').split('\0').filter(Boolean);
  if(flags.length===0||flags.length>MAX_PATHS)deny('BAD_INDEX_SIZE');
  const indexed=new Set();
  for(const record of flags){
    if(!record.startsWith('H ')||record.length<=2)deny('UNSAFE_INDEX_FLAGS');
    if(indexed.has(record.slice(2)))deny('DUPLICATE_INDEX_PATH');
    indexed.add(record.slice(2));
  }
  const raw=git(['ls-tree','-rz','--full-tree','HEAD'],root,gitBin);
  const tracked=new Map(),dirs=new Set(['']),names=new Set();
  for(const entry of raw.toString('utf8').split('\0').filter(Boolean)){
    const match=/^(100644|100755|120000) blob ([a-f0-9]{40})\t(.+)$/u.exec(entry);
    if(!match)deny('UNSUPPORTED_TREE_ENTRY');
    const [,mode,oid,path]=match;
    if(!asciiPath.test(path)||path.startsWith('/')||path.split('/').some(s=>s==='.'||s==='..'||!s)||path.normalize('NFC')!==path)deny('UNSAFE_GIT_TREE_PATH');
    if(path==='.git'||path.startsWith('.git/'))deny('GIT_CONTROL_PATH');
    if(tracked.has(path)||names.has(path.toLowerCase()))deny('DUPLICATE_OR_CASE_ALIAS');
    names.add(path.toLowerCase());tracked.set(path,{oid,mode});
    const segments=path.split('/');segments.pop();let dir='';
    for(const segment of segments){dir=dir?dir+'/'+segment:segment;dirs.add(dir);}
    if(tracked.size>MAX_PATHS)deny('TOO_MANY_SOURCE_FILES');
  }
  if(tracked.size===0||indexed.size!==tracked.size||[...tracked.keys()].some(x=>!indexed.has(x)))deny('INDEX_TREE_MISMATCH');

  const seen=new Set(),pending=[['',root]];
  while(pending.length){
    const [parent,absolute]=pending.pop();
    for(const entry of readdirSync(absolute,{withFileTypes:true})){
      if(!parent&&entry.name==='.git')continue;
      const p=parent?parent+'/'+entry.name:entry.name;
      if(!asciiPath.test(entry.name)||entry.name.normalize('NFC')!==entry.name)deny('UNSAFE_PHYSICAL_PATH');
      const location=join(root,...p.split('/')),stat=lstatSync(location);
      if(stat.isDirectory()){
        if(!dirs.has(p)||stat.isSymbolicLink())deny('UNTRACKED_DIRECTORY');
        pending.push([p,location]);continue;
      }
      const ref=tracked.get(p);
      if(!ref)deny('UNTRACKED_OR_IGNORED_PATH');
      if(ref.mode==='120000'){
        if(!stat.isSymbolicLink())deny('SYMLINK_MODE_CHANGED');
        // Source-bearing symlinks need separate sandbox/containment review.
        deny('SOURCE_SYMLINK_NOT_ADMITTED');
      }
      if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1)deny('FILE_TYPE_OR_LINK_CHANGED');
      if((stat.mode&0o111)!==(ref.mode==='100755'?0o111:0))deny('EXECUTABLE_MODE_CHANGED');
      if(stat.size>MAX_BLOB_BYTES)deny('OVERSIZED_BLOB');
      // Keep one O_NOFOLLOW descriptor open for the raw read; reject inode,
      // link-count, size, mode and timestamp swaps before or during the read.
      const fd=openSync(location,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
      try{
        const initial=fstatSync(fd);
        if(initial.dev!==stat.dev||initial.ino!==stat.ino||
           initial.nlink!==1||!initial.isFile()||initial.size>MAX_BLOB_BYTES)
          deny('SOURCE_INODE_REPLACED');
        const data=readFileSync(fd);
        const after=fstatSync(fd);
        if(after.dev!==initial.dev||after.ino!==initial.ino||after.nlink!==1||
           after.size!==initial.size||after.mode!==initial.mode||
           after.mtimeMs!==initial.mtimeMs||after.ctimeMs!==initial.ctimeMs)
          deny('SOURCE_CHANGED_DURING_READ');
        if(data.length!==initial.size||blobHash(data)!==ref.oid)
          deny('PHYSICAL_BLOB_CHANGED');
      }finally{closeSync(fd);}
      seen.add(p);
    }
  }
  if(seen.size!==tracked.size)deny('MISSING_TRACKED_SOURCE');
  return {classification:'EXACT_PHYSICAL_SOURCE',head,tree,checked_files:seen.size};
}
if(process.argv[1]?.endsWith('/verify_cli_ci_checkout_20261107.mjs')){
  try{
    if(process.argv.length!==2)deny('UNEXPECTED_ARGUMENTS');
    process.stdout.write(JSON.stringify(verifyCheckout())+'\n');
  }catch(e){process.stderr.write((e?.message||'SOURCE_UNVERIFIED')+'\n');process.exitCode=65;}
}
