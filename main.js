import * as bbs from '@digitalbazaar/bbs-signatures'

const {secretKey, publicKey} = await bbs.generateKeyPair({
  ciphersuite: 'BLS12-381-SHA-256'
});

// `header`
const header = new Uint8Array();
const presentationHeader = new Uint8Array();
// N-many `messages`, each is a `Uint8Array`, use `TextEncoder` to
// express strings as UTF-8 bytes
const messages = [new TextEncoder().encode('some message')];
const disclosedMessages = [new TextEncoder().encode('some message')];
const disclosedMessageIndexes = [0];
// `signature` is a `Uint8Array`

console.log(secretKey);
console.log(publicKey);

const signature = await bbs.sign({secretKey, publicKey, header, messages, ciphersuite: 'BLS12-381-SHA-256'});

console.log(signature);

// pass original signer's `publicKey`, `signature`, `header`, and `messages`
var verified = await bbs.verifySignature({
  publicKey, signature, header, messages,
  ciphersuite: 'BLS12-381-SHA-256'
});
// `verified` is a boolean

console.log(verified);

// pass original signer's `publicKey`, `signature`, `header`, and `messages`
// as well as a custom `presentationHeader` and any `disclosedMessageIndexes`
const proof = await bbs.deriveProof({
    publicKey, signature, header, messages,
    presentationHeader, disclosedMessageIndexes,
    ciphersuite: 'BLS12-381-SHA-256'
  });
  // `proof` is a `Uint8Array` containing a BBS proof

console.log(proof);

// pass `proof`, original signer's `publicKey` and`header`
// as well as holder's custom `presentationHeader`, `disclosedMessages`, and
// `disclosedMessageIndexes`
var verified = await bbs.verifyProof({
    publicKey, proof, header,
    presentationHeader, disclosedMessages, disclosedMessageIndexes,
    ciphersuite: 'BLS12-381-SHA-256'
  });
  // `verified` is a boolean


console.log(verified);