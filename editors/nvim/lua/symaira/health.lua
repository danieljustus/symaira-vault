local auth = require("symvault.auth")
local config = require("symvault.config")
local client = require("symvault.client")

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
    error("MCP token not found. Run 'symvault serve' to generate one.")
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
  client.health(function(health_status)
    if health_status then
      ok("MCP server is reachable and healthy")
    end
  end)
end

return M
