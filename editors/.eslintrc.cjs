module.exports = {
  root: true,
  env: {
    es2022: true,
    node: true,
    jest: true,
  },
  parser: "@typescript-eslint/parser",
  parserOptions: {
    ecmaVersion: "latest",
    sourceType: "module",
  },
  plugins: ["@typescript-eslint"],
  rules: {
    // TS equivalents: noUnusedLocals/noUnusedParameters and noFallthroughCasesInSwitch.
    // Lint also covers Jest files, which the shared tsc builds exclude.
    "@typescript-eslint/no-unused-vars": [
      "error",
      { argsIgnorePattern: "^_" },
    ],
    "no-fallthrough": "error",
    // Complements noImplicitAny by rejecting explicit any annotations.
    "@typescript-eslint/no-explicit-any": "error",
    // Small core rules without direct TypeScript compiler switches.
    eqeqeq: "error",
    "no-debugger": "error",
    "no-empty": "error",
  },
};
