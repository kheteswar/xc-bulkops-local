// ═══════════════════════════════════════════════════════════════════════════
// CONFIG DUMP - CHILD OBJECT RESOLVER
// Enhanced: parallel fetching, cache, retry, cancellation, relationship graph
// ═══════════════════════════════════════════════════════════════════════════

import { apiClient } from '../api';
import type {
  ObjectTypeDefinition, FetchedObject, FetchedChild,
  FetchOptions, GraphNode, GraphEdge, RelationshipGraphData,
} from './types';
import { OBJECT_TYPES } from './types';

// ═══════════════════════════════════════════════════════════════════════════
// OBJECT CACHE
// ═══════════════════════════════════════════════════════════════════════════

const objectCache = new Map<string, any>();

/** Clear the fetch cache (call between dump sessions). */
export function clearCache() {
  objectCache.clear();
}

function cacheKey(apiResource: string, namespace: string, name: string): string {
  return `${apiResource}:${namespace}/${name}`;
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Resolve a dot-path with [] array notation against an object.
 * e.g. "spec.default_route_pools[].pool" on a LB config
 * Returns an array of { name, namespace } refs found.
 */
function resolveRefPath(obj: any, path: string): { name: string; namespace?: string }[] {
  const refs: { name: string; namespace?: string }[] = [];
  const segments = path.split('.');

  function walk(current: any, segIdx: number) {
    if (current == null || segIdx >= segments.length) {
      if (current && typeof current === 'object' && current.name) {
        refs.push({ name: current.name, namespace: current.namespace });
      }
      return;
    }

    let seg = segments[segIdx];
    const isArrayAccess = seg.endsWith('[]');
    if (isArrayAccess) {
      seg = seg.slice(0, -2);
    }

    const next = current[seg];
    if (next == null) return;

    if (isArrayAccess && Array.isArray(next)) {
      for (const item of next) {
        walk(item, segIdx + 1);
      }
    } else if (isArrayAccess && typeof next === 'object' && !Array.isArray(next)) {
      walk(next, segIdx + 1);
    } else {
      walk(next, segIdx + 1);
    }
  }

  walk(obj, 0);
  return refs;
}

/**
 * Sanitize a string for use in filenames.
 */
export function sanitizeFilename(name: string): string {
  return name.replace(/[^a-zA-Z0-9._-]/g, '_').replace(/_+/g, '_');
}

// ═══════════════════════════════════════════════════════════════════════════
// FETCH WITH RETRY + CACHE
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Fetch a single object by type and name, with 1-retry and caching.
 */
async function fetchSingleObject(
  typeDef: ObjectTypeDefinition,
  namespace: string,
  name: string,
  signal?: AbortSignal,
): Promise<any> {
  // Check cache first
  const key = cacheKey(typeDef.apiResource, namespace, name);
  if (objectCache.has(key)) {
    return objectCache.get(key);
  }

  const endpoint = `/api/config/namespaces/${namespace}/${typeDef.apiResource}/${name}`;

  async function attemptFetch(ep: string, retries = 1): Promise<any> {
    for (let attempt = 0; attempt <= retries; attempt++) {
      if (signal?.aborted) throw new DOMException('Aborted', 'AbortError');
      try {
        const result = await apiClient.get<any>(ep);
        return result;
      } catch (e) {
        if (signal?.aborted) throw new DOMException('Aborted', 'AbortError');
        if (attempt === retries) throw e;
        // Backoff before retry
        await new Promise(r => setTimeout(r, 500 * (attempt + 1)));
      }
    }
  }

  try {
    const result = await attemptFetch(endpoint);
    objectCache.set(key, result);
    return result;
  } catch {
    // Try shared namespace as fallback
    if (namespace !== 'shared') {
      try {
        const sharedKey = cacheKey(typeDef.apiResource, 'shared', name);
        if (objectCache.has(sharedKey)) return objectCache.get(sharedKey);
        const result = await attemptFetch(`/api/config/namespaces/shared/${typeDef.apiResource}/${name}`);
        objectCache.set(sharedKey, result);
        return result;
      } catch {
        return null;
      }
    }
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// PARALLEL CHILD RESOLUTION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Recursively resolve a fetched object's child references.
 * Uses parallel fetching within each child group for speed.
 */
async function resolveChildren(
  config: any,
  typeDef: ObjectTypeDefinition,
  namespace: string,
  name: string,
  visited: Set<string>,
  maxDepth: number,
  options?: FetchOptions,
): Promise<FetchedObject> {
  const result: FetchedObject = {
    type: typeDef.id,
    name,
    namespace,
    config,
    children: [],
  };

  if (maxDepth <= 0 || typeDef.childRefs.length === 0) return result;

  for (const childRef of typeDef.childRefs) {
    // Check cancellation
    if (options?.signal?.aborted) return result;

    // Check if this child type is excluded
    if (options?.excludeChildTypes?.has(childRef.targetType)) continue;

    const refs = resolveRefPath(config, childRef.path);
    if (refs.length === 0) continue;

    const targetTypeDef = OBJECT_TYPES.find(t => t.id === childRef.targetType);
    if (!targetTypeDef) continue;

    const childGroup: FetchedChild = {
      label: childRef.label,
      type: childRef.targetType,
      objects: [],
    };

    // Deduplicate refs
    const uniqueRefs: { key: string; name: string; namespace: string }[] = [];
    const seen = new Set<string>();
    for (const ref of refs) {
      const ns = ref.namespace || namespace;
      const key = `${childRef.targetType}:${ns}/${ref.name}`;
      if (!visited.has(key) && !seen.has(key)) {
        seen.add(key);
        uniqueRefs.push({ key, name: ref.name, namespace: ns });
      }
    }

    // Mark all as visited before fetching (prevents parallel duplicates)
    for (const ref of uniqueRefs) {
      visited.add(ref.key);
    }

    // Parallel fetch all children in this group
    const fetchPromises = uniqueRefs.map(async (ref) => {
      if (options?.signal?.aborted) return null;
      const childConfig = await fetchSingleObject(targetTypeDef, ref.namespace, ref.name, options?.signal);
      if (childConfig) {
        return resolveChildren(childConfig, targetTypeDef, ref.namespace, ref.name, visited, maxDepth - 1, options);
      }
      return null;
    });

    const settledResults = await Promise.allSettled(fetchPromises);
    for (const settled of settledResults) {
      if (settled.status === 'fulfilled' && settled.value) {
        childGroup.objects.push(settled.value);
      }
    }

    if (childGroup.objects.length > 0) {
      result.children.push(childGroup);
    }
  }

  return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// PUBLIC API
// ═══════════════════════════════════════════════════════════════════════════

/**
 * List all objects of a given type in a namespace.
 */
export async function listObjects(
  typeDef: ObjectTypeDefinition,
  namespace: string,
): Promise<{ name: string; labels?: Record<string, string> }[]> {
  const endpoint = `/api/config/namespaces/${namespace}/${typeDef.apiResource}`;
  try {
    const response = await apiClient.get<{ items: any[] }>(endpoint);
    const items = response?.items || [];
    return items.map(item => ({
      name: item.metadata?.name || item.name || 'unknown',
      labels: item.metadata?.labels,
    }));
  } catch {
    return [];
  }
}

/**
 * Fetch a single object with its full config and recursively resolve all children.
 * Supports cancellation, caching, parallel child resolution, and excluded types.
 */
export async function fetchObjectWithChildren(
  typeDef: ObjectTypeDefinition,
  namespace: string,
  name: string,
  options?: FetchOptions,
): Promise<FetchedObject | null> {
  if (options?.signal?.aborted) return null;

  options?.onProgress?.({ phase: 'fetching', message: `Fetching ${typeDef.label}: ${name}`, current: 0, total: 1 });

  const config = await fetchSingleObject(typeDef, namespace, name, options?.signal);
  if (!config) return null;

  options?.onProgress?.({ phase: 'resolving', message: `Resolving child objects for ${name}...`, current: 0, total: 1 });

  const visited = new Set<string>();
  visited.add(`${typeDef.id}:${namespace}/${name}`);

  const result = await resolveChildren(config, typeDef, namespace, name, visited, 3, options);

  options?.onProgress?.({ phase: 'done', message: 'Done', current: 1, total: 1 });
  return result;
}

/**
 * Build a flat JSON bundle with the root object + all resolved children.
 */
export function buildConfigBundle(obj: FetchedObject): any {
  const bundle: any = {
    _type: obj.type,
    _name: obj.name,
    _namespace: obj.namespace,
    _exportedAt: new Date().toISOString(),
    config: obj.config,
    referenced_objects: {},
  };

  function collectChildren(node: FetchedObject) {
    for (const childGroup of node.children) {
      if (!bundle.referenced_objects[childGroup.type]) {
        bundle.referenced_objects[childGroup.type] = [];
      }
      for (const child of childGroup.objects) {
        // Avoid duplicates in the bundle
        const existing = bundle.referenced_objects[childGroup.type];
        if (!existing.some((e: any) => e.name === child.name && e.namespace === child.namespace)) {
          existing.push({
            name: child.name,
            namespace: child.namespace,
            config: child.config,
          });
        }
        collectChildren(child);
      }
    }
  }

  collectChildren(obj);
  return bundle;
}

/**
 * Build a CSV summary of all objects and their children.
 * Columns: RootObject, RootType, ChildObject, ChildType, ChildNamespace, Relationship
 */
export function buildCSV(results: FetchedObject[]): string {
  const rows: string[][] = [['Root Object', 'Root Type', 'Root Namespace', 'Child Object', 'Child Type', 'Child Namespace', 'Relationship']];

  function walkChildren(root: FetchedObject, node: FetchedObject) {
    for (const childGroup of node.children) {
      for (const child of childGroup.objects) {
        rows.push([
          root.name,
          root.type,
          root.namespace,
          child.name,
          child.type,
          child.namespace,
          childGroup.label,
        ]);
        walkChildren(root, child);
      }
    }
  }

  for (const obj of results) {
    // Add root object itself
    rows.push([obj.name, obj.type, obj.namespace, '', '', '', 'ROOT']);
    walkChildren(obj, obj);
  }

  return rows.map(row => row.map(cell => `"${cell.replace(/"/g, '""')}"`).join(',')).join('\n');
}

// ═══════════════════════════════════════════════════════════════════════════
// RELATIONSHIP GRAPH BUILDER
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Build a relationship graph from fetched results.
 * Tracks which objects are shared (referenced by multiple parents).
 */
export function buildRelationshipGraph(results: FetchedObject[]): RelationshipGraphData {
  const nodeMap = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];
  const parentCounts = new Map<string, number>();

  function nodeId(type: string, ns: string, name: string): string {
    return `${type}:${ns}/${name}`;
  }

  function ensureNode(obj: FetchedObject, isRoot: boolean): string {
    const id = nodeId(obj.type, obj.namespace, obj.name);
    if (!nodeMap.has(id)) {
      nodeMap.set(id, {
        id,
        type: obj.type,
        name: obj.name,
        namespace: obj.namespace,
        parentCount: 0,
        isRoot,
      });
    }
    return id;
  }

  function walkTree(parent: FetchedObject, isRoot: boolean) {
    const parentId = ensureNode(parent, isRoot);

    for (const childGroup of parent.children) {
      for (const child of childGroup.objects) {
        const childId = ensureNode(child, false);

        // Track parent count
        const count = (parentCounts.get(childId) || 0) + 1;
        parentCounts.set(childId, count);

        // Add edge (deduplicate)
        const edgeKey = `${parentId}->${childId}:${childGroup.label}`;
        if (!edges.some(e => `${e.source}->${e.target}:${e.label}` === edgeKey)) {
          edges.push({
            source: parentId,
            target: childId,
            label: childGroup.label,
          });
        }

        walkTree(child, false);
      }
    }
  }

  for (const result of results) {
    walkTree(result, true);
  }

  // Update parent counts
  for (const [id, count] of parentCounts) {
    const node = nodeMap.get(id);
    if (node) node.parentCount = count;
  }

  return {
    nodes: Array.from(nodeMap.values()),
    edges,
  };
}
