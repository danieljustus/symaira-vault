#!/bin/sh
# Real loader/setup smoke; no vault reads or network requests.
set -eu
plugin=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
nvim=$(command -v "${NVIM_BIN:-nvim}")
: "${PLENARY_PATH:?Set PLENARY_PATH to an existing plenary.nvim checkout}"
test -f "$PLENARY_PATH/lua/plenary/curl.lua"
test -x "$nvim"
umask 077
context=$(mktemp -d "${TMPDIR:-/tmp}/symaira-nvim-smoke.XXXXXX")
trap 'rm -rf -- "$context"' 0 HUP INT TERM
mkdir -p "$context/home" "$context/config" "$context/data" "$context/state" "$context/cache" "$context/tmp"
env -i PATH="$PATH" HOME="$context/home" \
  XDG_CONFIG_HOME="$context/config" XDG_DATA_HOME="$context/data" \
  XDG_STATE_HOME="$context/state" XDG_CACHE_HOME="$context/cache" \
  TMPDIR="$context/tmp" SYMVAULT_VAULT="$context/home/unused-vault" \
  SYMAIRA_PLUGIN="$plugin" PLENARY_PATH="$PLENARY_PATH" \
  "$nvim" --headless -u NONE -i NONE -n -c 'lua local ok, err = pcall(function()
    vim.opt.runtimepath:append(vim.env.PLENARY_PATH)
    vim.opt.runtimepath:append(vim.env.SYMAIRA_PLUGIN)
    assert(type(require("plenary.curl").post) == "function")
    require("symaira").setup({ timeout_ms = 1500 })
    for _, name in ipairs({"SymairaList", "SymairaGet", "SymairaCopy", "SymairaGenerate", "SymairaFind", "SymairaGenerateTOTP"}) do
      assert(vim.fn.exists(":" .. name) == 2, name .. " missing")
    end
    assert(require("symaira.config").get("timeout_ms") == 1500)
    assert(type(require("symaira.health").check) == "function")
    assert(#vim.api.nvim_get_runtime_file("lua/symaira/health.lua", false) == 1)
    assert(require("symaira.masking").mask_value("synthetic") == "***")
    assert(type(vim.fn.SymairaCurlRequest) == "function")
    assert(type(vim.fn.SymairaCurlGet) == "function")
  end); if not ok then io.stderr:write(tostring(err) .. "\n"); vim.cmd("cquit 1") else print("Symaira loader/setup smoke passed"); vim.cmd("qa!") end'
