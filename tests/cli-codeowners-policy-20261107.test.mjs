import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';

const policyUrl = new URL('../.github/CODEOWNERS', import.meta.url);
const expected = Object.freeze([
  '*', '/.github/', '/.oreslang/', '/crates/', '/docs/',
  '/packaging/', '/scripts/', '/specs/', '/tools/', '/tests/',
  '/Cargo.toml', '/Cargo.lock', '/.cli-flags.toml',
  '/.gitignore', '/README.md',
]);
const owner = '@ORESoftware';
function decodePolicy(bytes){
  assert.ok(Buffer.isBuffer(bytes), 'raw policy must be a Buffer');
  assert.ok(!(bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf), 'BOM forbidden');
  return new TextDecoder('utf-8', {fatal:true,ignoreBOM:true}).decode(bytes);
}
const source = decodePolicy(readFileSync(policyUrl));

function validate(text) {
  assert.equal(typeof text, 'string');
  assert.ok(text.length > 0 && Buffer.byteLength(text, 'utf8') < 3 * 1024 * 1024);
  assert.equal(text.normalize('NFC'), text, 'policy must use normalized Unicode');
  assert.ok(!/[\u0000-\u0009\u000B-\u001F\u007F\u200B-\u200F\u202A-\u202E\u2066-\u2069]/u.test(text), 'no control/hidden characters');
  assert.ok(text.endsWith('\n'), 'a trailing newline is required');

  const lines = text.split('\n').filter(Boolean);
  const rules = [];
  for (const line of lines) {
    if (line.startsWith('#')) continue;
    const match = /^(\*|\/[a-zA-Z0-9_.-]+(?:\/[a-zA-Z0-9_.-]+)*\/?) (@[a-zA-Z0-9-]+)$/.exec(line);
    assert.ok(match, 'malformed rule or unrecognized rule-owner pair');
    assert.equal(match[2], owner, 'each path must require independent named owner');
    rules.push(match[1]);
  }
  assert.deepEqual(rules, expected, 'no missing, extra, duplicated or shadowing rules');
  return rules;
}

function matches(pattern, file) {
  if (pattern === '*') return true;
  const path = pattern.slice(1);
  return pattern.endsWith('/') ? file.startsWith(path) : file === path;
}

test('all sensitive AttoLang CLI roots are pinned to independently-owned rules', () => {
  const rules = validate(source);
  for (const path of [
    '.github/CODEOWNERS', '.github/workflows/ci.yml', '.oreslang/config',
    'crates/atto/src/main.rs', 'docs/security.md', 'packaging/homebrew/generate-formula.sh',
    'scripts/test_release_archive.py', 'specs/MergeAssurancePublicCanaryV1.tla',
    'tools/verify.mjs', 'tests/cli-codeowners-policy-20261107.test.mjs',
    'Cargo.toml', 'Cargo.lock', '.cli-flags.toml', '.gitignore',
    'README.md', 'unlisted/future_sensitive_file',
  ]) {
    assert.equal(rules.filter(pattern => matches(pattern, path)).length >= 1, true, path);
  }
});

test('missing global owner, sensitive subtree or manifest entry fails closed', () => {
  for (const path of expected) {
    const changed = source.replace(path + ' ' + owner + '\n', '');
    assert.notEqual(changed, source, path);
    assert.throws(() => validate(changed), path);
  }
});

test('reject self-ownership, spoofed owner, duplicate and shadow ownership rules', () => {
  const mutants = [
    source.replace('* ' + owner, '* @the1mills'),
    source.replace('* ' + owner, '* @ORESOFTWARE'),
    source + '/crates/ @the1mills\n',
    source + '* @ORESoftware\n',
    source.replace('/.github/ @ORESoftware\n', '/.github/ @the1mills\n'),
    source.replace('/.github/ @ORESoftware\n', '/.github/ @ORESoftware @the1mills\n'),
    source.replace('/.github/ @ORESoftware\n', '/.github/ @ORESoftware\n/.github/workflows/ @the1mills\n'),
    source.replace('/Cargo.toml @ORESoftware\n', '/Cargo.toml @ORESoftware\n/UNEXPECTED @ORESoftware\n'),
  ];
  for (const [index, mutant] of mutants.entries()) assert.throws(() => validate(mutant), String(index));
});

test('reject invisible Unicode, CRLF, malformed syntax and noncanonical ordering', () => {
  const mutants = [
    source.replace('/crates/', '/crates/\u200b'),
    source.replace('/crates/', '/crates/\u202e'),
    source.replace(/\n/g, '\r\n'),
    source.replace('/crates/ @ORESoftware', '/crates/\t@ORESoftware'),
    source.replace('/crates/ @ORESoftware', '/crates/  @ORESoftware'),
    source.replace('/crates/ @ORESoftware', ' /crates/ @ORESoftware'),
    source.replace('/crates/ @ORESoftware', '/crates/** @ORESoftware'),
    source.replace('/crates/ @ORESoftware', '/crates/ @ORESoftware # shadow'),
    source.replace('/crates/ @ORESoftware\n/docs/ @ORESoftware', '/docs/ @ORESoftware\n/crates/ @ORESoftware'),
    source.trimEnd(),
  ];
  for (const [index, mutant] of mutants.entries()) assert.throws(() => validate(mutant), String(index));
});

test('empty or all-comments policy cannot pass', () => {
  for (const mutant of ['', '# no ownership\n', '# hidden\n* @other\n']) {
    assert.throws(() => validate(mutant));
  }
});


// Independent cases, not just subcases embedded in one all-or-nothing loop.
for (const rule of expected) {
  test('fail closed if required CODEOWNERS rule is missing: '+rule, () => {
    const changed = source.replace(rule+' '+owner+'\n', '');
    assert.notEqual(changed,source);
    assert.throws(() => validate(changed));
  });
}
const extraMutations = [
  ['extra owner on root', source.replace('* @ORESoftware','* @ORESoftware @the1mills')],
  ['injected alternate group', source.replace('* @ORESoftware','* @ORESoftware @untrusted-team')],
  ['path glob override', source+'\n** @the1mills\n'],
  ['malicious test override', source+'/tests/ @the1mills\n'],
  ['malicious workflow override', source+'/.github/workflows/ @the1mills\n'],
  ['malicious security script override', source+'/scripts/ @the1mills\n'],
  ['mixed-case owner in final match', source.replace('/Cargo.toml @ORESoftware','/Cargo.toml @oreSoftware')],
  ['malformed colon owner',source.replace('/docs/ @ORESoftware','/docs/: @ORESoftware')],
  ['comment placement shadow',source.replace('/docs/ @ORESoftware','# /docs/ @ORESoftware')],
  ['trailing whitespace',source.replace('/docs/ @ORESoftware','/docs/ @ORESoftware ')],
  ['leading whitespace',source.replace('/docs/ @ORESoftware',' /docs/ @ORESoftware')],
  ['tab-delimited owner',source.replace('/docs/ @ORESoftware','/docs/\t@ORESoftware')],
  ['control byte in comment',source.replace('# AttoLang','#\u0001 AttoLang')],
  ['UTF8 invisibility in comment',source.replace('# AttoLang','#\u200d AttoLang')],
  ['BIDI direction override',source.replace('/tools/','/to\u202eols/')],
  ['bidirectional isolate',source.replace('/tools/','/tools/\u2067')],
  ['accidental blank wildcard',source.replace('* @ORESoftware','')],
  ['missing last newline',source.slice(0,-1)],
  ['bare escaped wildcard',source.replace('* @ORESoftware','\\* @ORESoftware')],
  ['Windows path separators',source.replace('/scripts/','\\scripts\\')],
  ['quoted CODEOWNERS pattern',source.replace('/scripts/','"/scripts/"')],
  ['double wildcard',source.replace('* @ORESoftware','** @ORESoftware')],
  ['path with parent traversal',source.replace('/tools/','/docs/../tools/')],
  ['dangerous path exception',source+'!/tools/ @the1mills\n'],
  ['duplicate owner override',source+'/README.md @ORESoftware\n'],
];
for (const [title,mutant] of extraMutations) {
  test('reject CODEOWNERS policy mutation: '+title,()=>assert.throws(()=>validate(mutant)));
}
for(const [label,bytes] of [
  ['invalid UTF8 lead',Buffer.from([0xc0,0xaf])],
  ['invalid continuation',Buffer.from([0x80])],
  ['truncated UTF8',Buffer.from([0xe2,0x82])],
  ['non-UTF8 byte',Buffer.from([0xff])],
  ['NUL in file',Buffer.concat([Buffer.from(source,'utf8'),Buffer.from([0])])],
  ['BOM prefix',Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),Buffer.from(source,'utf8')])],
]) {
  test('reject malformed or unsafe raw CODEOWNERS bytes: '+label,()=>{
    assert.throws(()=>validate(decodePolicy(bytes)));
  });
}
test('reject invalid decoder inputs',()=>{
  for(const candidate of ['',null,{},42]) assert.throws(()=>decodePolicy(candidate));
});
test('accept only exact NFC policy text parsed from actual raw file',()=>{
  assert.equal(decodePolicy(readFileSync(policyUrl)),source);
  assert.deepEqual(validate(source),expected);
});
