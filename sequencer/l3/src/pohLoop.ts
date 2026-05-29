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
 * Start the PoH slot-subscription loop for the L3 sequencer.
 *
 * Same cross-boundary logic as L2: seals whenever
 *   floor(slot / slotsPerBatch) > floor(watermark / slotsPerBatch)
 * so missed slots are handled correctly on reconnect.
 */
export function startPohLoop(config: SequencerConfig, db: DatabaseType): void {
  let retryDelay = 1_000;

  function connect(): void {
    console.log(`[PoH] Connecting to ${config.l1WsUrl} …`);
    const ws = new WebSocket(config.l1WsUrl);

    ws.on('open', () => {
      retryDelay = 1_000;
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

      const watermark = getSlotWatermark(db, 'L3');
      const lastBoundary = Math.floor(watermark / config.slotsPerBatch);
      const thisBoundary = Math.floor(slot / config.slotsPerBatch);

      if (thisBoundary > lastBoundary) {
        sealAndSubmit(config, db, slot)
          .then(result => {
            if (result) {
              console.log(
                `[PoH] ✅ Batch #${result.batchId} sealed @ slot ${slot} — ` +
                `root=${result.merkleRoot.slice(0, 16)}… nfts=${result.entryCount}`,
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
