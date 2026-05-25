local M = {}

local function vault_path()
  return vim.env.SYMVAULT_VAULT or vim.fn.expand("~/.symvault")
end

--- Read the MCP bearer token from the token file.
---@return string|nil token, or nil if not found.
function M.read_token()
  local token_file = vim.fn.resolve(vault_path() .. "/mcp-token")
  local ok, content = pcall(vim.fn.readfile, token_file)
  if not ok or not content or #content == 0 then
    return nil
  end
  return vim.trim(content[1])
end

--- Build auth headers for MCP HTTP requests.
---@return table Headers map.
function M.build_headers()
  local config = require("symvault.config")
  local token = M.read_token()
  return {
    ["Content-Type"] = "application/json",
    ["Accept"] = "application/json",
    ["Authorization"] = "Bearer " .. (token or ""),
    ["X-Symaira-Agent"] = config.get("agent_name"),
    ["MCP-Protocol-Version"] = "2025-11-25",
  }
end

return M
