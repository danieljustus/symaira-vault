export function maskValue(value: string, maskChar = "*"): string {
  if (!value || value.length === 0) {
    return "";
  }
  // Always show 3 mask chars regardless of value length
  return maskChar.repeat(3);
}

/**
 * Recursively mask all values in an object while preserving structure.
 * Keys like 'path', 'meta', 'type' are preserved unmasked.
 */
export function maskObject(
  obj: Record<string, unknown>,
  preserveKeys: string[] = ["path", "meta", "type", "name", "version", "created", "updated"]
): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(obj)) {
    if (preserveKeys.includes(key)) {
      result[key] = value;
    } else if (typeof value === "string") {
      result[key] = maskValue(value);
    } else if (typeof value === "object" && value !== null) {
      result[key] = maskObject(value as Record<string, unknown>, preserveKeys);
    } else {
      result[key] = value;
    }
  }

  return result;
}

/**
 * Mask an Entry's data fields while preserving metadata.
 */
export function maskEntryData(entry: {
  path: string;
  data: Record<string, unknown>;
  meta: unknown;
}): { path: string; data: Record<string, unknown>; meta: unknown } {
  return {
    path: entry.path,
    data: maskObject(entry.data),
    meta: entry.meta,
  };
}
