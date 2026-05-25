-- Symaira Neovim plugin configuration defaults
local M = {}

M.defaults = {
  base_url = "http://127.0.0.1:8080",
  agent_name = "nvim",
  timeout_ms = 30000,
  masking_char = "*",
  -- Keys whose values are never masked in UI
  preserve_keys = { "path", "meta", "type", "name", "version", "created", "updated" },
}

M.options = {}

--- Merge user options with defaults.
---@param opts table|nil User-provided configuration overrides.
function M.setup(opts)
  M.options = vim.tbl_deep_extend("force", M.defaults, opts or {})
end

--- Get a config value by key with optional default.
---@param key string
---@param default any
---@return any
function M.get(key, default)
  if M.options[key] ~= nil then
    return M.options[key]
  end
  return default or M.defaults[key]
end

return M
