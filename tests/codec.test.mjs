import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

// Exercise the codec shipped on the page, rather than a separate implementation.
const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
const script = html.match(/<script>\s*(const codec = [\s\S]*?)<\/script>/)?.[1];
assert.ok(script, 'The page must include its codec');
const { codec } = vm.runInNewContext(`${script}\n({ codec });`, {
  atob, btoa, TextEncoder, Uint8Array,
}, { timeout: 5000 });

test('ASCII tags retain trimming and case-insensitive matching', () => {
  assert.equal(codec.normalizeTag('  Player#12345  '), 'player#12345');
});

test('accepts accented letters, including the characters in issue #1', () => {
  for (const letter of ['á', 'ē', 'ĕ', 'ė', 'ę', 'ě']) {
    assert.equal(codec.normalizeTag(`Ab${letter}#12345`), `ab${letter}#12345`);
  }
});

test('preserves non-ASCII case as Lua byte-oriented lower does', () => {
  assert.equal(codec.normalizeTag('ÉCLAIR#12345'), 'Éclair#12345');
});

test('still rejects malformed tags and preserves the existing length limits', () => {
  for (const tag of [
    '', 'Ab#1234', '1Player#12345', 'Player', 'Player#123',
    'Player#12345678901', 'PlayerNameTooLong#1234', 'Pla yer#1234',
    'Player##1234', 'Play_er#1234', 'Pla<yer#1234', 'Player#１２３４',
  ]) {
    assert.throws(() => codec.normalizeTag(tag), /Enter a full BattleTag/, tag);
  }
});

// Fixed reference outputs for plaintext bytes 00..1f, independently calculated
// from RXPGuides GuideLoader.lua's ReadCacheData / CheckDataIntegrity byte rules:
// ASCII lowercase, UTF-8 bytes, final 16 bytes, zero padding, key mixing, then RC4.
const vectors = [
  ['Player#12345', '2c98cedee56612443c7670dbbcbce58247438a419243ca48d0c5946bd117669f'],
  ['Málaga#12345', 'bf830219f7190d32a637705ec3b96a3df9bac06b47b183a4c44654b5dfbef7ee'],
  ['Éclair#12345', '2d995f2d02270fdf2e47d04bdae099978219910f716937e91671009c63394f86'],
  ['Řehoř#12345', 'e296f3f1d265423871bdd22fe12b3ab6987a95263fad188eab1be5f4f9411098'],
  ['玩家名字#12345', '987ebf986127b15e1e2d2ca3aeff80dc7214d2e5713c43ed68f54bf62090c5bf'],
  // The 16-byte suffix begins inside a UTF-8 character; slicing characters fails.
  [`A${'é'.repeat(11)}#1234567890`, 'a4e9fff331f35ece74658e4ccee4ad29d327b1331eb2d8ca04d4591083749819'],
];
const plaintext = Uint8Array.from({ length: 32 }, (_, i) => i);

for (const [tag, expectedHex] of vectors) {
  test(`matches the reference ciphertext for ${tag}`, () => {
    assert.equal(Buffer.from(codec.crypt(plaintext, tag)).toString('hex'), expectedHex);
  });
}

test('generates the expected import envelope for an accented tag', () => {
  const bundle = {
    count: 1, version: 40000,
    blocks: [{ checksum: 12345, data: Buffer.from(plaintext).toString('base64') }],
  };
  const expected = Buffer.from(vectors[1][1], 'hex').toString('base64');
  assert.equal(codec.generate(bundle, 'Málaga#12345'), `1|12345:${expected}%|40000`);
});
