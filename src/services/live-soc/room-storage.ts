// =============================================================================
// Live SOC Monitoring Room — Room Storage (localStorage CRUD)
// =============================================================================

import type { SOCRoomConfig, Baseline } from './types';

// ---------------------------------------------------------------------------
// Storage Keys
// ---------------------------------------------------------------------------

const STORAGE_KEYS = {
  ROOMS: 'soc_rooms',
  BASELINE_PREFIX: 'soc_baseline_',
  LAST_ROOM: 'soc_lastRoom',
} as const;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function readJSON<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    if (raw === null) return fallback;
    return JSON.parse(raw) as T;
  } catch {
    console.warn(`[SOC Storage] Failed to parse key "${key}", returning fallback`);
    return fallback;
  }
}

function writeJSON(key: string, value: unknown): void {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch (err) {
    console.error(`[SOC Storage] Failed to write key "${key}"`, err);
  }
}

// ---------------------------------------------------------------------------
// Room CRUD
// ---------------------------------------------------------------------------

/**
 * Returns all saved SOC rooms, sorted by lastOpenedAt descending.
 */
export function getRooms(): SOCRoomConfig[] {
  const rooms = readJSON<SOCRoomConfig[]>(STORAGE_KEYS.ROOMS, []);
  return rooms.sort(
    (a, b) => new Date(b.lastOpenedAt).getTime() - new Date(a.lastOpenedAt).getTime()
  );
}

/**
 * Saves a room configuration. If a room with the same id exists, it is replaced.
 * Otherwise, the room is appended.
 */
export function saveRoom(room: SOCRoomConfig): void {
  const rooms = readJSON<SOCRoomConfig[]>(STORAGE_KEYS.ROOMS, []);
  const idx = rooms.findIndex((r) => r.id === room.id);
  if (idx >= 0) {
    rooms[idx] = room;
  } else {
    rooms.push(room);
  }
  writeJSON(STORAGE_KEYS.ROOMS, rooms);
}

/**
 * Deletes a room by id. Also removes its associated baseline.
 */
export function deleteRoom(id: string): void {
  const rooms = readJSON<SOCRoomConfig[]>(STORAGE_KEYS.ROOMS, []);
  const filtered = rooms.filter((r) => r.id !== id);
  writeJSON(STORAGE_KEYS.ROOMS, filtered);

  // Clean up associated baseline
  try {
    localStorage.removeItem(`${STORAGE_KEYS.BASELINE_PREFIX}${id}`);
  } catch {
    // Ignore cleanup errors
  }

  // Clear last room if it was the deleted one
  if (getLastRoomId() === id) {
    try {
      localStorage.removeItem(STORAGE_KEYS.LAST_ROOM);
    } catch {
      // Ignore
    }
  }
}

/**
 * Returns a room by id, or null if not found.
 */
export function getRoomById(id: string): SOCRoomConfig | null {
  const rooms = readJSON<SOCRoomConfig[]>(STORAGE_KEYS.ROOMS, []);
  return rooms.find((r) => r.id === id) ?? null;
}

// ---------------------------------------------------------------------------
// Baseline Persistence
// ---------------------------------------------------------------------------

/**
 * Retrieves the persisted baseline for a room.
 */
export function getBaseline(roomId: string): Baseline | null {
  const key = `${STORAGE_KEYS.BASELINE_PREFIX}${roomId}`;
  return readJSON<Baseline | null>(key, null);
}

/**
 * Persists a baseline for a room.
 */
export function saveBaseline(roomId: string, baseline: Baseline): void {
  const key = `${STORAGE_KEYS.BASELINE_PREFIX}${roomId}`;
  writeJSON(key, baseline);
}

// ---------------------------------------------------------------------------
// Last Opened Room
// ---------------------------------------------------------------------------

/**
 * Returns the id of the last-opened room (for auto-resume).
 */
export function getLastRoomId(): string | null {
  try {
    return localStorage.getItem(STORAGE_KEYS.LAST_ROOM);
  } catch {
    return null;
  }
}

/**
 * Sets the last-opened room id.
 */
export function setLastRoomId(id: string): void {
  try {
    localStorage.setItem(STORAGE_KEYS.LAST_ROOM, id);
  } catch {
    // Ignore write errors
  }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/**
 * Returns the total number of saved rooms.
 */
export function getRoomCount(): number {
  return readJSON<SOCRoomConfig[]>(STORAGE_KEYS.ROOMS, []).length;
}

/**
 * Clears all SOC storage (rooms, baselines, last room).
 * Useful for debugging or reset scenarios.
 */
export function clearAllSOCStorage(): void {
  const rooms = readJSON<SOCRoomConfig[]>(STORAGE_KEYS.ROOMS, []);
  for (const room of rooms) {
    try {
      localStorage.removeItem(`${STORAGE_KEYS.BASELINE_PREFIX}${room.id}`);
    } catch {
      // Continue cleanup
    }
  }
  try {
    localStorage.removeItem(STORAGE_KEYS.ROOMS);
    localStorage.removeItem(STORAGE_KEYS.LAST_ROOM);
  } catch {
    // Ignore
  }
}
