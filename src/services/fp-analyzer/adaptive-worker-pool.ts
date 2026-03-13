/**
 * Adaptive Worker Pool
 *
 * Executes an array of async tasks with dynamic concurrency controlled by
 * an AdaptiveConcurrencyController. Workers spawn and park based on the
 * controller's current concurrency level. 429 errors trigger re-queuing
 * with backoff.
 */

import type { AdaptiveConcurrencyController } from './adaptive-concurrency';

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export interface AdaptivePoolResult<T> {
  id: number;
  result?: T;
  error?: Error;
}

export async function runAdaptivePool<T>(
  tasks: Array<{ id: number; execute: () => Promise<T> }>,
  controller: AdaptiveConcurrencyController,
  onResult?: (r: AdaptivePoolResult<T>) => void,
  onProgress?: (completed: number, total: number) => void,
  cancelledFn?: () => boolean,
): Promise<void> {
  const queue = [...tasks];
  let completed = 0;
  let activeWorkers = 0;

  return new Promise<void>((resolve, reject) => {
    function spawnWorker() {
      activeWorkers++;
      (async () => {
        while (queue.length > 0) {
          // Check cancellation
          if (cancelledFn?.()) {
            activeWorkers--;
            if (activeWorkers === 0) resolve();
            return;
          }

          // Park if too many workers active
          if (activeWorkers > controller.concurrency) {
            activeWorkers--;
            return;
          }

          // Apply inter-request delay
          const delay = controller.getRequestDelay();
          if (delay > 0) await sleep(delay);

          const task = queue.shift();
          if (!task) break;

          try {
            const result = await task.execute();
            controller.recordSuccess();
            onResult?.({ id: task.id, result });
          } catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            if (msg.includes('429')) {
              controller.recordRateLimit();
              queue.unshift(task); // Re-queue
              await sleep(controller.getRequestDelay());
            } else {
              controller.recordError();
              onResult?.({ id: task.id, error: err instanceof Error ? err : new Error(msg) });
            }
          }

          completed++;
          onProgress?.(completed, tasks.length);

          // Spawn additional workers if controller allows more
          if (controller.concurrency > activeWorkers && queue.length > 0) {
            spawnWorker();
          }
        }

        activeWorkers--;
        if (activeWorkers === 0 && queue.length === 0) resolve();
      })().catch(reject);
    }

    if (tasks.length === 0) {
      resolve();
      return;
    }

    const initial = Math.min(controller.concurrency, tasks.length);
    for (let i = 0; i < initial; i++) {
      spawnWorker();
    }
  });
}
