local auth = require("symaira.auth")
local config = require("symaira.config")
local client = require("symaira.client")

local M = {}

local function start()
  vim.health.start("Symaira")
end

local function ok(msg)
  vim.health.ok(msg)
end

local function warn(msg)
  vim.health.warn(msg)
end

local function error(msg)
  vim.health.error(msg)
end

function M.check()
  start()

  -- Check MCP token
  local token = auth.read_token()
  if token then
    ok("MCP token found at ~/.symvault/mcp-token")
  else
    error("MCP token not found. Run 'symvault mcp' to generate one.")
  end

  -- Check config
  local base_url = config.get("base_url")
  ok("Server URL: " .. base_url)

  -- Check plenary.nvim availability
  local has_plenary, _ = pcall(require, "plenary.curl")
  if has_plenary then
    ok("plenary.nvim is available")
  else
    warn("plenary.nvim not found (required for HTTP requests)")
  end

  -- Check if Symaira CLI is available
  local has_symvault = vim.fn.executable("symvault") == 1
  if has_symvault then
    ok("symvault CLI is available")
  else
    warn("symvault CLI not found in PATH")
  end

  -- Test server connectivity (async - reports after delay)
  if not rawget(vim.fn, "SymairaCurlGet") then
    warn("Run require('symaira').setup() before testing server connectivity")
    return
  end
  client.health(function(err, health_data)
    if not err and health_data then
      ok("MCP server is reachable and healthy")
    elseif err then
      error("MCP server health check failed: " .. tostring(err))
    end
  end)
end

return M
