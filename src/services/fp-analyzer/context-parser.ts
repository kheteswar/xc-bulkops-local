/**
 * Parse security event context string into structured exclusion rule context.
 * e.g. "parameter (input_file)" → { contextType: "CONTEXT_PARAMETER", contextName: "input_file" }
 */
export function parseContext(contextStr: string): { contextType: string; contextName: string } {
  const str = (contextStr || '').trim();

  const match = str.match(/^(parameter|cookie|header)\s*\(([^)]+)\)/i);
  if (match) {
    const typeMap: Record<string, string> = {
      parameter: 'CONTEXT_PARAMETER',
      cookie: 'CONTEXT_COOKIE',
      header: 'CONTEXT_HEADER',
    };
    return { contextType: typeMap[match[1].toLowerCase()], contextName: match[2].trim() };
  }

  if (/url|uri/i.test(str)) return { contextType: 'CONTEXT_URL', contextName: '' };
  if (/body/i.test(str)) return { contextType: 'CONTEXT_BODY', contextName: '' };

  return { contextType: 'CONTEXT_PARAMETER', contextName: '' };
}
