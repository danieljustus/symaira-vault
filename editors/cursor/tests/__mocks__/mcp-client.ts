export function maskValue(value: string): string {
  if (!value || value.length === 0) {
    return "";
  }
  return "*".repeat(3);
}

export class SymairaTools {
  constructor() {}
}
