/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  roots: ["<rootDir>/tests"],
  testMatch: ["**/*.test.ts"],
  moduleNameMapper: {
    "^vscode$": "<rootDir>/tests/__mocks__/vscode.ts",
    "^@symaira/mcp-client$": "<rootDir>/tests/__mocks__/mcp-client.ts",
  },
  moduleFileExtensions: ["ts", "js", "json"],
  transform: {
    "^.+\\.ts$": [
      "ts-jest",
      {
        diagnostics: false,
      },
    ],
  },
};
