local config = require("symaira.config")
local commands = require("symaira.commands")
local client = require("symaira.client")
local health = require("symaira.health")

local M = {}

local function setup_curl_helpers()
  local curl = require("plenary.curl")

  ---@diagnostic disable-next-line: unused-function
  vim.fn["SymairaCurlRequest"] = function(body, headers, callback)
    local response = curl.post(config.get("base_url") .. "/mcp", {
      body = body,
      headers = headers,
      timeout = config.get("timeout_ms"),
      raw = { "--max-time", tostring(config.get("timeout_ms") // 1000) },
    })

    vim.schedule(function()
      if response.exit ~= 0 then
        callback(
          string.format(
            "HTTP %d: %s (connection refused? Is 'symaira serve' running?)",
            response.status,
            response.exit
          ),
          nil
        )
        return
      end

      if response.status >= 400 then
        local msg = response.body or ""
        if response.status == 401 then
          callback("Authentication failed. Check your MCP token.", nil)
        elseif response.status == 403 then
          callback("Forbidden. Check X-Symaira-Agent header.", nil)
        else
          callback(string.format("HTTP %d: %s", response.status, msg), nil)
        end
        return
      end

      callback(nil, response.body)
    end)
  end

  ---@diagnostic disable-next-line: unused-function
  vim.fn["SymairaCurlGet"] = function(url, headers, callback)
    local response = curl.get(url, {
      headers = headers,
      timeout = config.get("timeout_ms"),
      raw = { "--max-time", tostring(config.get("timeout_ms") // 1000) },
    })

    vim.schedule(function()
      if response.exit ~= 0 then
        callback(
          string.format(
            "HTTP %d: Connection failed. Is 'symaira serve' running?",
            response.status
          ),
          nil
        )
        return
      end
      callback(nil, response.body)
    end)
  end
end

--- Setup the plugin. Must be called by the user.
---@param opts table|nil Configuration overrides (see symaira.config.defaults).
function M.setup(opts)
  config.setup(opts)

  local ok, _ = pcall(require, "plenary.curl")
  if not ok then
    vim.notify(
      "Symaira: plenary.nvim is required. Install 'nvim-lua/plenary.nvim'.",
      vim.log.levels.ERROR
    )
    return
  end

  setup_curl_helpers()
  commands.register()

  vim.api.nvim_create_augroup("Symaira", { clear = true })
  vim.api.nvim_create_autocmd("VimLeavePre", {
    group = "Symaira",
    callback = function()
      client.close()
    end,
  })

  vim.health._symaira = health.check
end

return M
