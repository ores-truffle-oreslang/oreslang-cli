import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, renameSync, symlinkSync, linkSync, chmodSync, unlinkSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { verifyCheckout } from '../scripts/verify_cli_ci_checkout_20261107.mjs';

const validEnv=Object.freeze({});
function git(root,...args){return execFileSync('/usr/bin/git',args,{cwd:root,encoding:'utf8',env:{PATH:'/usr/bin:/bin',HOME:'/tmp',LC_ALL:'C'}}).trim();}
function fixture(t){
  const root=mkdtempSync(join(tmpdir(),'atto-source-proof-'));
  t.after(()=>rmSync(root,{recursive:true,force:true}));
  git(root,'init','-q');git(root,'config','user.email','ci-test@example.invalid');git(root,'config','user.name','CI Fixture');
  mkdirSync(join(root,'.github'));mkdirSync(join(root,'src'));
  writeFileSync(join(root,'.github','CODEOWNERS'),'* @ORESoftware\n');
  writeFileSync(join(root,'src','main.atto'),'fnc main(): int { return 7; }\n');
  writeFileSync(join(root,'.gitignore'),'ignored.tmp\n');
  git(root,'add','.');git(root,'commit','-qm','initial source');
  return {root,expected:git(root,'rev-parse','HEAD')};
}
function inspect(f,options={}){return verifyCheckout({...f,environment:validEnv,...options});}
function denied(t,mutate,reason){const f=fixture(t);mutate(f);assert.throws(()=>inspect(f),new RegExp(reason));}

test('exact physical blobs, root, tree and ordinary index flags admit clean source',t=>{
  const f=fixture(t),r=inspect(f);
  assert.equal(r.classification,'EXACT_PHYSICAL_SOURCE');assert.equal(r.head,f.expected);
  assert.match(r.tree,/^[a-f0-9]{40}$/);assert.equal(r.checked_files,3);
});
const adversaries=[
 ['modified tracked bytes, even with clean index',f=>writeFileSync(join(f.root,'src/main.atto'),'malicious script\n'),'PHYSICAL_BLOB_CHANGED'],
 ['staged replacement',f=>{writeFileSync(join(f.root,'src/main.atto'),'replacement\n');git(f.root,'add','src/main.atto');},'PHYSICAL_BLOB_CHANGED'],
 ['deleted tracked source',f=>unlinkSync(join(f.root,'src/main.atto')),'MISSING_TRACKED_SOURCE'],
 ['untracked file',f=>writeFileSync(join(f.root,'src/untracked.atto'),'hostile\n'),'UNTRACKED_OR_IGNORED_PATH'],
 ['ignored file (git status silently skips)',f=>writeFileSync(join(f.root,'ignored.tmp'),'hostile\n'),'UNTRACKED_OR_IGNORED_PATH'],
 ['ignored nested file',f=>writeFileSync(join(f.root,'ignored.tmp'),'a'),'UNTRACKED_OR_IGNORED_PATH'],
 ['case alias under ignorecase',f=>{git(f.root,'config','core.ignorecase','true');writeFileSync(join(f.root,'SRC'),'shadow');},'UNTRACKED_OR_IGNORED_PATH'],
 ['case aliased tracked filename',f=>writeFileSync(join(f.root,'src/MAIN.atto'),'hostile'),'UNTRACKED_OR_IGNORED_PATH'],
 ['assume-unchanged bit',f=>git(f.root,'update-index','--assume-unchanged','src/main.atto'),'UNSAFE_INDEX_FLAGS'],
 ['assume-unchanged plus physical edit',f=>{git(f.root,'update-index','--assume-unchanged','src/main.atto');writeFileSync(join(f.root,'src/main.atto'),'mutated');},'UNSAFE_INDEX_FLAGS'],
 ['skip-worktree bit',f=>git(f.root,'update-index','--skip-worktree','src/main.atto'),'UNSAFE_INDEX_FLAGS'],
 ['skip-worktree plus changed source',f=>{git(f.root,'update-index','--skip-worktree','src/main.atto');writeFileSync(join(f.root,'src/main.atto'),'mutated');},'UNSAFE_INDEX_FLAGS'],
 ['regular file becomes symlink',f=>{unlinkSync(join(f.root,'src/main.atto'));symlinkSync('../.github/CODEOWNERS',join(f.root,'src/main.atto'));},'FILE_TYPE_OR_LINK_CHANGED'],
 ['directory becomes symlink',f=>{renameSync(join(f.root,'src'),join(f.root,'source-real'));symlinkSync('source-real',join(f.root,'src'));},'UNTRACKED_DIRECTORY'],
 ['hardlinked source',f=>linkSync(join(f.root,'src/main.atto'),join(f.root,'.git','test-hardlink')),'FILE_TYPE_OR_LINK_CHANGED'],
 ['symlinked unexpected path',f=>symlinkSync('.github/CODEOWNERS',join(f.root,'new-policy')),'UNTRACKED_OR_IGNORED_PATH'],
 ['executable bit flip',f=>chmodSync(join(f.root,'src/main.atto'),0o755),'EXECUTABLE_MODE_CHANGED'],
 ['untracked empty directory',f=>mkdirSync(join(f.root,'new-dir')),'UNTRACKED_DIRECTORY'],
 ['untracked nested directory',f=>{mkdirSync(join(f.root,'new-dir'));mkdirSync(join(f.root,'new-dir','sub'));},'UNTRACKED_DIRECTORY'],
 ['untracked path in existing source directory',f=>mkdirSync(join(f.root,'src','nested')),'UNTRACKED_DIRECTORY'],
 ['untracked .gitignore override',f=>writeFileSync(join(f.root,'.gitignore'),'new-ignored\n'),'PHYSICAL_BLOB_CHANGED'],
 ['NUL-free Unicode filename shadow',f=>writeFileSync(join(f.root,'src','foo\u200b.atto'),'hostile'),'UNTRACKED_OR_IGNORED_PATH'],
 ['non-NFC filename',f=>writeFileSync(join(f.root,'src','a\u0301.atto'),'hostile'),'UNSAFE_PHYSICAL_PATH'],
 ['unexpected Windows-style archive alias',f=>writeFileSync(join(f.root,'src','BACK\\SLASH'),'hostile'),'UNTRACKED_OR_IGNORED_PATH'],
 ['source commit changes',f=>{writeFileSync(join(f.root,'src/main.atto'),'new');git(f.root,'add','.');git(f.root,'commit','-qm','new head');},'HEAD_CHANGED'],
];
for(const [title,mutate,reason] of adversaries)test(title,t=>denied(t,mutate,reason));
for(const [name,control] of Object.entries({
  GIT_DIR:'other.git',GIT_WORK_TREE:'/tmp',GIT_INDEX_FILE:'/tmp/alt',
  GIT_OBJECT_DIRECTORY:'/tmp/alt',GIT_CONFIG_COUNT:'1',GIT_CONFIG_KEY_0:'core.ignorecase',
  GIT_CONFIG_VALUE_0:'true',GIT_NO_REPLACE_OBJECTS:'0'
})){
  test('reject inherited '+name,t=>{const f=fixture(t);assert.throws(()=>inspect(f,{environment:{[name]:control}}),/INHERITED_GIT_CONTROL/);});
}
for(const bad of ['','xyz','f'.repeat(39),'F'.repeat(40),'f'.repeat(41),'../index','0'.repeat(64)]){
  test('reject malformed expected HEAD '+JSON.stringify(bad),t=>{const f=fixture(t);assert.throws(()=>inspect(f,{expected:bad}),/EXPECTED_HEAD_INVALID/);});
}
test('reject valid but wrong original HEAD',t=>{const f=fixture(t);assert.throws(()=>inspect(f,{expected:'a'.repeat(40)}),/HEAD_CHANGED/);});
test('detect source edits made with identical file length',t=>{
  const f=fixture(t),p=join(f.root,'src/main.atto'),v=readFileSync(p);
  v[0]^=0x01;writeFileSync(p,v);assert.throws(()=>inspect(f),/PHYSICAL_BLOB_CHANGED/);
});
