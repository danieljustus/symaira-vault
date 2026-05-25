local config = require("symvault.config")
local auth = require("symvault.auth")

local M = {}

local id_counter = 0

local function next_id()
  id_counter = id_counter + 1
  return tostring(id_counter)
end

local function build_request(method, params)
  return {
    jsonrpc = "2.0",
    id = next_id(),
    method = method,
    params = params or vim.empty_dict(),
  }
end

--- Send a JSON-RPC 2.0 request to the MCP server.
---@param method string JSON-RPC method.
---@param params table Parameters for the method.
---@param callback function Callback receiving (err, result).
local function send_request(method, params, callback)
  local body = vim.json.encode(build_request(method, params))
  local headers = auth.build_headers()

  vim.fn["SymairaCurlRequest"](body, headers, function(err, response_body)
    if err then
      callback(err, nil)
      return
    end

    local ok, decoded = pcall(vim.json.decode, response_body)
    if not ok then
      callback("Failed to parse JSON-RPC response", nil)
      return
    end

    if decoded.error then
      callback(
        string.format(
          "MCP Error %s: %s",
          tostring(decoded.error.code),
          tostring(decoded.error.message)
        ),
        nil
      )
      return
    end

    callback(nil, decoded.result)
  end)
end

--- Initialize the MCP session.
---@param callback function Called with (err).
function M.initialize(callback)
  local params = {
    protocolVersion = "2025-11-25",
    capabilities = {},
    clientInfo = {
      name = "symvault-nvim",
      version = "1.0.0",
    },
  }
  send_request("initialize", params, function(err)
    callback(err)
  end)
end

--- Call an MCP tool by name with arguments.
---@param tool_name string
---@param arguments table
---@param callback function Called with (err, result_table).
function M.call_tool(tool_name, arguments, callback)
  local params = {
    name = tool_name,
    arguments = arguments or {},
  }
  send_request("tools/call", params, function(err, result)
    if err then
      callback(err, nil)
      return
    end

    if type(result) == "table" and result.content then
      local combined_text = {}
      for _, item in ipairs(result.content) do
        if item.type == "text" then
          table.insert(combined_text, item.text)
        end
      end
      callback(nil, {
        text = table.concat(combined_text, "\n"),
        is_error = result.isError or false,
        content = result.content,
      })
    else
      callback(nil, result)
    end
  end)
end

--- Check server health by hitting /health endpoint.
---@param callback function Called with (err, health_data).
function M.health(callback)
  local url = config.get("base_url") .. "/health"
  local headers = { Accept = "application/json" }
  vim.fn["SymairaCurlGet"](url, headers, function(err, response_body)
    if err then
      callback(err, nil)
      return
    end
    local ok, decoded = pcall(vim.json.decode, response_body)
    if not ok then
      callback("Failed to parse health response", nil)
      return
    end
    callback(nil, decoded)
  end)
end

function M.close()
  id_counter = 0
end

return M
