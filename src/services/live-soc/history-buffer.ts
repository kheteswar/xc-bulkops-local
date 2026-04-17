// =============================================================================
// Live SOC Monitoring Room — History Buffer (Ring Buffer)
// =============================================================================
// Generic RingBuffer class for bounded-memory storage of time series data,
// cycle snapshots, and event feed entries.
//
// Buffer sizes (from spec Section 14):
//   - Time series: 288 points (24h at 5min intervals)
//   - Snapshots:   72 entries (6h at 5min intervals)
//   - Events:      1000 entries
// =============================================================================

import type { TimeSeriesPoint, CycleSnapshot, EventFeedEntry } from './types';

// ---------------------------------------------------------------------------
// Generic RingBuffer Class
// ---------------------------------------------------------------------------

/**
 * A fixed-size circular buffer that overwrites the oldest entries when full.
 * Provides O(1) push and O(1) indexed access.
 */
export class RingBuffer<T> {
  private buffer: (T | undefined)[];
  private head: number = 0;    // Next write position
  private count: number = 0;   // Current number of items
  private readonly maxSize: number;

  constructor(maxSize: number) {
    if (maxSize <= 0) throw new Error('RingBuffer maxSize must be > 0');
    this.maxSize = maxSize;
    this.buffer = new Array(maxSize);
  }

  /**
   * Adds an item to the buffer. If the buffer is full, the oldest item
   * is overwritten.
   */
  push(item: T): void {
    this.buffer[this.head] = item;
    this.head = (this.head + 1) % this.maxSize;
    if (this.count < this.maxSize) {
      this.count++;
    }
  }

  /**
   * Gets the item at the given logical index (0 = oldest, length-1 = newest).
   * Returns undefined if index is out of range.
   */
  get(index: number): T | undefined {
    if (index < 0 || index >= this.count) return undefined;
    const actualIndex = this.resolveIndex(index);
    return this.buffer[actualIndex];
  }

  /**
   * Returns all items in order from oldest to newest.
   */
  getAll(): T[] {
    if (this.count === 0) return [];
    const result: T[] = [];
    for (let i = 0; i < this.count; i++) {
      const item = this.buffer[this.resolveIndex(i)];
      if (item !== undefined) result.push(item);
    }
    return result;
  }

  /**
   * Returns the number of items currently in the buffer.
   */
  get length(): number {
    return this.count;
  }

  /**
   * Returns the most recently added item, or undefined if empty.
   */
  get latest(): T | undefined {
    if (this.count === 0) return undefined;
    const latestIndex = (this.head - 1 + this.maxSize) % this.maxSize;
    return this.buffer[latestIndex];
  }

  /**
   * Removes all items from the buffer.
   */
  clear(): void {
    this.buffer = new Array(this.maxSize);
    this.head = 0;
    this.count = 0;
  }

  /**
   * Returns all items as a plain array (oldest to newest). Alias for getAll().
   */
  toArray(): T[] {
    return this.getAll();
  }

  /**
   * Returns the maximum capacity of the buffer.
   */
  get capacity(): number {
    return this.maxSize;
  }

  /**
   * Returns true if the buffer is at full capacity.
   */
  get isFull(): boolean {
    return this.count === this.maxSize;
  }

  /**
   * Returns the oldest item, or undefined if empty.
   */
  get oldest(): T | undefined {
    if (this.count === 0) return undefined;
    return this.buffer[this.resolveIndex(0)];
  }

  /**
   * Returns the last N items (newest first), up to the current count.
   */
  getLastN(n: number): T[] {
    const take = Math.min(n, this.count);
    const result: T[] = [];
    for (let i = this.count - take; i < this.count; i++) {
      const item = this.buffer[this.resolveIndex(i)];
      if (item !== undefined) result.push(item);
    }
    return result;
  }

  /**
   * Iterates over all items from oldest to newest.
   */
  forEach(callback: (item: T, index: number) => void): void {
    for (let i = 0; i < this.count; i++) {
      const item = this.buffer[this.resolveIndex(i)];
      if (item !== undefined) callback(item, i);
    }
  }

  /**
   * Maps items from oldest to newest.
   */
  map<U>(callback: (item: T, index: number) => U): U[] {
    const result: U[] = [];
    this.forEach((item, i) => result.push(callback(item, i)));
    return result;
  }

  /**
   * Filters items from oldest to newest.
   */
  filter(predicate: (item: T, index: number) => boolean): T[] {
    const result: T[] = [];
    this.forEach((item, i) => {
      if (predicate(item, i)) result.push(item);
    });
    return result;
  }

  // -------------------------------------------------------------------------
  // Internal
  // -------------------------------------------------------------------------

  /**
   * Converts a logical index (0 = oldest) to the actual buffer index.
   */
  private resolveIndex(logicalIndex: number): number {
    if (this.count < this.maxSize) {
      // Buffer not yet full: items start at index 0
      return logicalIndex;
    }
    // Buffer is full: oldest item is at head (which is the next write position)
    return (this.head + logicalIndex) % this.maxSize;
  }
}

// ---------------------------------------------------------------------------
// Factory Functions
// ---------------------------------------------------------------------------

/**
 * Creates a ring buffer for time series data points.
 * Capacity: 288 (24 hours at 5-minute intervals).
 */
export function createTimeSeriesBuffer(): RingBuffer<TimeSeriesPoint> {
  return new RingBuffer<TimeSeriesPoint>(288);
}

/**
 * Creates a ring buffer for cycle snapshots (full state capture per cycle).
 * Capacity: 72 (6 hours at 5-minute intervals).
 */
export function createSnapshotBuffer(): RingBuffer<CycleSnapshot> {
  return new RingBuffer<CycleSnapshot>(72);
}

/**
 * Creates a ring buffer for live event feed entries.
 * Capacity: 1000 entries.
 */
export function createEventBuffer(): RingBuffer<EventFeedEntry> {
  return new RingBuffer<EventFeedEntry>(1000);
}
