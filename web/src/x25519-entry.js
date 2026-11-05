// The only cryptographic primitive the browser needs: X25519 public-key
// derivation from a locally generated private key.
export { x25519 } from '@noble/curves/ed25519.js';
