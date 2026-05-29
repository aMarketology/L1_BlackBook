import WebSocket from 'ws';
import { getSlotWatermark } from '@bb/shared';
import type { SequencerConfig, DatabaseType } from '@bb/shared';
import { sealAndSubmit } from './batchSealer.js';

interface SlotNotification {
  method: string;
  params?: {
    result?: {
      slot: number;
    };
  };
}

/**
 * Start the PoH slot-subscription loop.
 *
 * Connects to the L1 WebSocket, subscribes to slot notifications, and calls
 * `sealAndSubmit` whenever we cross a batch boundary since the last watermark.
 * The boundary check handles missed slots correctly: if the sequencer was
 * offline and missed slot 25, it will seal when it receives slot 26.
 *
 * Auto-reconnects with exponential backoff (cap: 30 s).
 */
export function startPohLoop(config: SequencerConfig, db: DatabaseType): void {
  let retryDelay = 1_000;

  function connect(): void {
    console.log(`[PoH] Connecting to ${config.l1WsUrl} …`);
    const ws = new WebSocket(config.l1WsUrl);

    ws.on('open', () => {
      retryDelay = 1_000; // reset backoff on successful connect
      console.log('[PoH] Connected — subscribing to slot notifications');
      ws.send(JSON.stringify({ method: 'slotSubscribe' }));
    });

    ws.on('message', (data: WebSocket.RawData) => {
      let msg: SlotNotification;
      try {
        msg = JSON.parse(data.toString()) as SlotNotification;
      } catch {
        return;
      }

      if (msg.method !== 'slotNotification') return;
      const slot = msg.params?.result?.slot;
      if (typeof slot !== 'number') return;

      // Cross-boundary check: seal if we've passed at least one new batch boundary.
      const watermark = getSlotWatermark(db, 'L5');
      const lastBoundary = Math.floor(watermark / config.slotsPerBatch);
      const thisBoundary = Math.floor(slot / config.slotsPerBatch);

      if (thisBoundary > lastBoundary) {
        sealAndSubmit(config, db, slot)
          .then(result => {
            if (result) {
              console.log(
                `[PoH] ✅ Batch #${result.batchId} sealed @ slot ${slot} — ` +
                `root=${result.merkleRoot.slice(0, 16)}… entries=${result.entryCount}`,
              );
            }
          })
          .catch((err: unknown) => {
            const msg = err instanceof Error ? err.message : String(err);
            console.error(`[PoH] ❌ sealAndSubmit failed @ slot ${slot}: ${msg}`);
          });
      }
    });

    ws.on('error', (err: Error) => {
      console.error('[PoH] WebSocket error:', err.message);
    });

    ws.on('close', () => {
      console.warn(`[PoH] Disconnected — reconnecting in ${retryDelay / 1000}s`);
      setTimeout(() => {
        retryDelay = Math.min(retryDelay * 2, 30_000);
        connect();
      }, retryDelay);
    });
  }

  connect();
}
