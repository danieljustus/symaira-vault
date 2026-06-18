import { validateBaseUrl, SymairaMCPClient, SymairaURLError } from "../src";

describe("validateBaseUrl", () => {
  describe("valid loopback URLs", () => {
    const validUrls = [
      { url: "http://127.0.0.1:8080", label: "127.0.0.1 with port" },
      { url: "http://127.0.0.1:3000", label: "127.0.0.1 with alternate port" },
      { url: "http://localhost:8080", label: "localhost with port" },
      { url: "http://localhost:3000", label: "localhost with alternate port" },
      { url: "http://[::1]:8080", label: "IPv6 loopback [::1]" },
      { url: "http://0.0.0.0:8080", label: "0.0.0.0 with port" },
      { url: "https://127.0.0.1:8080", label: "https 127.0.0.1" },
      { url: "https://localhost:8080", label: "https localhost" },
      { url: "https://[::1]:8080", label: "https IPv6 loopback" },
      { url: "https://0.0.0.0:8080", label: "https 0.0.0.0" },
      { url: "http://127.0.0.1", label: "127.0.0.1 no port" },
      { url: "http://localhost", label: "localhost no port" },
    ];

    test.each(validUrls)("$label — $url should be accepted", ({ url }) => {
      expect(() => validateBaseUrl(url)).not.toThrow();
    });
  });

  describe("invalid non-loopback URLs", () => {
    const invalidUrls = [
      { url: "http://example.com:8080", label: "external domain" },
      { url: "https://evil.com", label: "evil domain" },
      { url: "http://192.168.1.1:8080", label: "private LAN IP" },
      { url: "http://10.0.0.1:8080", label: "private class A IP" },
      { url: "http://172.16.0.1:8080", label: "private class B IP" },
      { url: "http://attacker.example.com/token", label: "attacker domain with path" },
    ];

    test.each(invalidUrls)("$label — $url should be rejected", ({ url }) => {
      expect(() => validateBaseUrl(url)).toThrow(SymairaURLError);
      expect(() => validateBaseUrl(url)).toThrow(/loopback/i);
    });
  });

  describe("invalid protocols", () => {
    const protocolUrls = [
      { url: "ftp://127.0.0.1:8080", label: "ftp" },
      { url: "file:///etc/passwd", label: "file protocol" },
      { url: "javascript:alert(1)", label: "javascript protocol" },
      { url: "data:text/html,<h1>xss</h1>", label: "data protocol" },
    ];

    test.each(protocolUrls)("$label — $url should be rejected", ({ url }) => {
      expect(() => validateBaseUrl(url)).toThrow(SymairaURLError);
    });
  });

  describe("malformed / edge cases", () => {
    test("empty string throws SymairaURLError", () => {
      expect(() => validateBaseUrl("")).toThrow(SymairaURLError);
      expect(() => validateBaseUrl("")).toThrow(/Invalid URL/);
    });

    test("missing protocol throws SymairaURLError", () => {
      expect(() => validateBaseUrl("127.0.0.1:8080")).toThrow(SymairaURLError);
    });

    test("random garbage throws SymairaURLError", () => {
      expect(() => validateBaseUrl("not-a-url")).toThrow(SymairaURLError);
    });
  });
});

describe("SymairaMCPClient constructor validation", () => {
  test("accepts default baseUrl (http://127.0.0.1:8080)", () => {
    expect(() => new SymairaMCPClient()).not.toThrow();
  });

  test("accepts explicit loopback URL", () => {
    expect(
      () => new SymairaMCPClient({ baseUrl: "http://localhost:3000" })
    ).not.toThrow();
  });

  test("rejects non-loopback URL", () => {
    expect(
      () => new SymairaMCPClient({ baseUrl: "http://evil.com:8080" })
    ).toThrow(SymairaURLError);
  });

  test("rejects private IP", () => {
    expect(
      () => new SymairaMCPClient({ baseUrl: "http://192.168.1.1:8080" })
    ).toThrow(SymairaURLError);
  });
});
