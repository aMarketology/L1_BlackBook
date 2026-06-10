import express from 'express';
import { ed25519 as ed } from '@noble/curves/ed25519';
import { hexToBytes } from '@noble/hashes/utils';
import type { SequencerConfig, DatabaseType } from '@bb/shared';

// ─── Base58 address helper ────────────────────────────────────────────────────
// Converts a 32-byte hex Ed25519 public key to its base58 wallet address.
// Used so the transfer ownership check works whether the mint stored the
// address as base58 (the normal wallet format) or as hex.
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function pubkeyHexToAddress(hex: string): string {
  const bytes = hexToBytes(hex);
  let num = BigInt('0x' + Buffer.from(bytes).toString('hex'));
  const base = BigInt(58);
  let result = '';
  while (num > 0n) {
    result = BASE58_ALPHABET[Number(num % base)] + result;
    num = num / base;
  }
  for (const byte of bytes) {
    if (byte !== 0) break;
    result = '1' + result;
  }
  return result;
}
import { buildMerkleTree } from '@bb/shared';
import type { NftEntry } from '@bb/shared';
import {
  mintNft,
  transferNft,
  getNft,
  getCollection,
  getNftsByOwner,
  getAllNftSnapshots,
} from './nftEngine.js';
import { sealAndSubmit } from './batchSealer.js';

// ─── Ed25519 helper ───────────────────────────────────────────────────────────

function verifyEd25519(message: string, signatureHex: string, publicKeyHex: string): boolean {
  try {
    const sig = hexToBytes(signatureHex);
    const pk  = hexToBytes(publicKeyHex);
    const msg = new TextEncoder().encode(message);
    return ed.verify(sig, msg, pk);
  } catch {
    return false;
  }
}

// ─── Server factory ───────────────────────────────────────────────────────────

export function createServer(config: SequencerConfig, db: DatabaseType) {
  const app = express();
  app.use(express.json());

  // ── GET /health ───────────────────────────────────────────────────────────
  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', rollup_id: config.rollupId, port: config.port });
  });

  // ── POST /mint ───────────────────────────────────────────────────────────
  // Mint a new NFT.
  //
  // Body: { collection_id, token_id, owner_address, metadata_hash,
  //         metadata_uri, public_key, signature, timestamp, nonce }
  // Signed message: "L3_MINT:{collection_id}:{token_id}:{owner_address}:{metadata_hash}:{timestamp}:{nonce}"
  //
  // The signer is the collection creator / minting authority.
  // TODO: enforce per-collection minting policy in production.
  app.post('/mint', (req, res) => {
    const {
      collection_id, token_id, owner_address,
      metadata_hash, metadata_uri,
      public_key, signature, timestamp, nonce,
    } = req.body as {
      collection_id?: string; token_id?: string; owner_address?: string;
      metadata_hash?: string; metadata_uri?: string;
      public_key?: string; signature?: string; timestamp?: number; nonce?: string;
    };

    if (!collection_id || !token_id || !owner_address || !metadata_hash || !metadata_uri ||
        !public_key || !signature || !timestamp || !nonce) {
      res.status(400).json({ error: 'collection_id, token_id, owner_address, metadata_hash, metadata_uri, public_key, signature, timestamp, nonce are all required' });
      return;
    }

    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - timestamp) > 60) {
      res.status(400).json({ error: 'timestamp outside ±60 s window' });
      return;
    }

    const message = `L3_MINT:${collection_id}:${token_id}:${owner_address}:${metadata_hash}:${timestamp}:${nonce}`;
    if (!verifyEd25519(message, signature, public_key)) {
      res.status(401).json({ error: 'Invalid signature' });
      return;
    }

    try {
      mintNft(db, collection_id, token_id, owner_address, metadata_hash, metadata_uri);
      res.status(201).json({ collection_id, token_id, owner_address, metadata_hash });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      // SQLite UNIQUE constraint fires here for duplicate mints
      res.status(409).json({ error: msg });
    }
  });

  // ── POST /transfer ───────────────────────────────────────────────────────
  // Transfer NFT ownership.  Signed by the current owner.
  //
  // Body: { collection_id, token_id, new_owner,
  //         public_key, signature, timestamp, nonce }
  // Signed message: "L3_TRANSFER:{collection_id}:{token_id}:{new_owner}:{timestamp}:{nonce}"
  //
  // The signer's public_key must equal the current owner_address on record.
  app.post('/transfer', (req, res) => {
    const {
      collection_id, token_id, new_owner,
      public_key, signature, timestamp, nonce,
    } = req.body as {
      collection_id?: string; token_id?: string; new_owner?: string;
      public_key?: string; signature?: string; timestamp?: number; nonce?: string;
    };

    if (!collection_id || !token_id || !new_owner ||
        !public_key || !signature || !timestamp || !nonce) {
      res.status(400).json({ error: 'collection_id, token_id, new_owner, public_key, signature, timestamp, nonce are all required' });
      return;
    }

    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - timestamp) > 60) {
      res.status(400).json({ error: 'timestamp outside ±60 s window' });
      return;
    }

    const message = `L3_TRANSFER:${collection_id}:${token_id}:${new_owner}:${timestamp}:${nonce}`;
    if (!verifyEd25519(message, signature, public_key)) {
      res.status(401).json({ error: 'Invalid signature' });
      return;
    }

    // Verify signer is the current owner.
    // owner_address is stored as base58 wallet address; public_key is 64-char hex.
    // Derive the base58 address from the hex key so the formats match.
    const nft = getNft(db, collection_id, token_id);
    if (!nft) {
      res.status(404).json({ error: `NFT ${collection_id}/${token_id} not found` });
      return;
    }
    const signerAddress = pubkeyHexToAddress(public_key);
    if (nft.owner_address !== signerAddress) {
      res.status(403).json({ error: `Signer is not the owner of ${collection_id}/${token_id}` });
      return;
    }

    try {
      transferNft(db, collection_id, token_id, signerAddress, new_owner);
      res.json({ collection_id, token_id, new_owner });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(400).json({ error: msg });
    }
  });

  // ── GET /nfts/:collectionId/:tokenId ──────────────────────────────────────
  app.get('/nfts/:collectionId/:tokenId', (req, res) => {
    const nft = getNft(db, req.params.collectionId, req.params.tokenId);
    if (!nft) { res.status(404).json({ error: 'NFT not found' }); return; }
    res.json(nft);
  });

  // ── GET /nfts/:collectionId ───────────────────────────────────────────────
  app.get('/nfts/:collectionId', (req, res) => {
    res.json(getCollection(db, req.params.collectionId));
  });

  // ── GET /owner/:address ───────────────────────────────────────────────────
  app.get('/owner/:address', (req, res) => {
    res.json(getNftsByOwner(db, req.params.address));
  });

  // ── POST /admin/seal ──────────────────────────────────────────────────────
  // Force an immediate batch seal regardless of slot boundary.
  // Returns the batch_id, merkle_root, and per-NFT Merkle proofs so the
  // smoke test can build exit requests without waiting for 25 slots.
  // NOT authenticated — local-dev / test use only.
  app.post('/admin/seal', async (req, res) => {
    const snapshots = getAllNftSnapshots(db);
    if (snapshots.length === 0) {
      res.status(409).json({ error: 'No NFTs in the database — nothing to seal.' });
      return;
    }

    let result;
    try {
      result = await sealAndSubmit(config, db, 0);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(502).json({ error: `L1 submit_root failed: ${msg}` });
      return;
    }

    if (!result) {
      res.status(409).json({ error: 'sealAndSubmit returned null (empty snapshot).' });
      return;
    }

    // Build the Merkle tree again locally to extract per-leaf proofs.
    const entries: NftEntry[] = snapshots.map(s => ({
      type: 'NFT',
      collectionId: s.collectionId,
      tokenId: s.tokenId,
      owner: s.owner,
      metadataHash: s.metadataHash,
    }));
    const { root, proofs } = buildMerkleTree('L3', entries);

    const proofMap = entries.map((e, i) => ({
      collection_id: e.collectionId,
      token_id: e.tokenId,
      owner: e.owner,
      metadata_hash: e.metadataHash,
      siblings: proofs[i],
      // sibling_is_right is all false — sorted-pair hash_pair is commutative,
      // so direction is irrelevant to the L1 Rust verifier.
      sibling_is_right: proofs[i].map(() => false),
    }));

    res.json({
      batch_id: result.batchId,
      merkle_root: root,
      entry_count: result.entryCount,
      proofs: proofMap,
    });
  });

  return app;
}
