import {
  sanitizeEntryPath,
  validateContextFilePath,
  buildContextBlock,
} from "../src/cursorContext";

describe("sanitizeEntryPath", () => {
  it("returns normal paths unchanged", () => {
    expect(sanitizeEntryPath("github/password")).toBe("github/password");
    expect(sanitizeEntryPath("work/aws.access-key")).toBe("work/aws.access-key");
  });

  it("escapes LF (\\n) characters", () => {
    expect(sanitizeEntryPath("github\npassword")).toBe("github\\npassword");
  });

  it("escapes CR (\\r) characters", () => {
    expect(sanitizeEntryPath("github\rpassword")).toBe("github\\rpassword");
  });

  it("escapes CRLF (\\r\\n) as a single unit", () => {
    expect(sanitizeEntryPath("github\r\npassword")).toBe("github\\r\\npassword");
  });

  it("escapes backtick characters", () => {
    expect(sanitizeEntryPath("github`injection")).toBe("github\\`injection");
  });

  it("escapes pipe characters", () => {
    expect(sanitizeEntryPath("github|injection")).toBe("github\\|injection");
  });

  it("escapes pre-existing backslashes before other escapes", () => {
    // A raw backslash must not be able to combine with an added escape and
    // break out of the intended escaping (js/incomplete-sanitization).
    expect(sanitizeEntryPath("github\\injection")).toBe("github\\\\injection");
    expect(sanitizeEntryPath("github\\`injection")).toBe(
      "github\\\\\\`injection"
    );
  });

  it("handles multiple injection vectors in one path", () => {
    const malicious = "github\n`malicious`|table";
    expect(sanitizeEntryPath(malicious)).toBe(
      "github\\n\\`malicious\\`\\|table"
    );
  });

  it("handles empty string", () => {
    expect(sanitizeEntryPath("")).toBe("");
  });
});

describe("validateContextFilePath", () => {
  const workspace = "/home/user/project";

  it("accepts valid relative paths", () => {
    expect(validateContextFilePath(".cursorrules", workspace)).toBe(
      "/home/user/project/.cursorrules"
    );
    expect(validateContextFilePath("subdir/.cursorrules", workspace)).toBe(
      "/home/user/project/subdir/.cursorrules"
    );
  });

  it("rejects absolute paths starting with /", () => {
    expect(() =>
      validateContextFilePath("/etc/passwd", workspace)
    ).toThrow("must be relative");
  });

  it("rejects absolute Windows paths (C:\\) on Windows", () => {
    if (process.platform !== "win32") {
      return;
    }
    expect(() =>
      validateContextFilePath("C:\\Windows\\System32", workspace)
    ).toThrow("must be relative");
  });

  it("rejects paths containing .. traversal", () => {
    expect(() =>
      validateContextFilePath("../../etc/passwd", workspace)
    ).toThrow('".."');
  });

  it("rejects paths that resolve outside workspace", () => {
    expect(() =>
      validateContextFilePath("subdir/../../escape", workspace)
    ).toThrow('".."');
  });

  it("accepts paths that stay within workspace", () => {
    const result = validateContextFilePath("deep/nested/.cursorrules", workspace);
    expect(result).toBe("/home/user/project/deep/nested/.cursorrules");
  });
});

describe("buildContextBlock", () => {
  it("returns empty message when no entries", () => {
    const block = buildContextBlock([]);
    expect(block).toContain("No Symaira Vault secrets available.");
  });

  it("sanitizes entry paths with newline injection", () => {
    const entries = ["github\n# This is a injected rule"];
    const block = buildContextBlock(entries);
    expect(block).toContain("github\\n# This is a injected rule");
    expect(block).not.toContain("# This is a injected rule\n");
  });

  it("sanitizes entry paths with backtick injection", () => {
    const entries = ["github`system prompt override`"];
    const block = buildContextBlock(entries);
    expect(block).toContain("github\\`system prompt override\\`");
  });

  it("sanitizes entry paths with pipe injection", () => {
    const entries = ["github| malicious | column"];
    const block = buildContextBlock(entries);
    expect(block).toContain("github\\| malicious \\| column");
  });

  it("preserves context markers", () => {
    const block = buildContextBlock(["safe/entry"]);
    expect(block).toContain("<!-- SYMAIRA VAULT CONTEXT -->");
    expect(block).toContain("<!-- END SYMAIRA VAULT CONTEXT -->");
  });
});
