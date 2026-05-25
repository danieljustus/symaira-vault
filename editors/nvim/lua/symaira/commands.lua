local client = require("symvault.client")
local picker = require("symvault.picker")

local M = {}

--- Create all user commands.
function M.register()
  vim.api.nvim_create_user_command("SymairaList", function()
    picker.pick_vault_entry()
  end, {})

  vim.api.nvim_create_user_command("SymairaGet", function(info)
    local path = info.args
    if path == "" then
      picker.pick_vault_entry({
        prompt = "Symaira: Get Entry",
        on_select = function(selected_path)
          M.get_entry_at_cursor(selected_path)
        end,
      })
      return
    end
    M.get_entry_at_cursor(path)
  end, { nargs = "?" })

  vim.api.nvim_create_user_command("SymairaCopy", function(info)
    local path = info.args
    if path == "" then
      picker.pick_vault_entry({
        prompt = "Symaira: Copy to Clipboard",
        on_select = function(selected_path)
          M.copy_to_clipboard(selected_path)
        end,
      })
      return
    end
    M.copy_to_clipboard(path)
  end, { nargs = "?" })

  vim.api.nvim_create_user_command("SymairaGenerate", function(info)
    local length = tonumber(info.args) or 24
    M.generate_password(length)
  end, { nargs = "?" })

  vim.api.nvim_create_user_command("SymairaFind", function(info)
    local query = info.args
    if query == "" then
      vim.ui.input({ prompt = "Symaira Search: " }, function(input)
        if input and input ~= "" then
          M.find_entries(input)
        end
      end)
      return
    end
    M.find_entries(query)
  end, { nargs = "?" })

  vim.api.nvim_create_user_command("SymairaGenerateTOTP", function(info)
    local path = info.args
    if path == "" then
      picker.pick_vault_entry({
        prompt = "Symaira: Generate TOTP",
        on_select = function(selected_path)
          M.generate_totp(selected_path)
        end,
      })
      return
    end
    M.generate_totp(path)
  end, { nargs = "?" })
end

--- Get an entry and insert its password at cursor position.
---@param path string
function M.get_entry_at_cursor(path)
  client.call_tool("get_entry", { path = path }, function(err, result)
    if err then
      vim.notify("Symaira: " .. err, vim.log.levels.ERROR)
      return
    end

    local text = ""
    if result and result.content then
      for _, item in ipairs(result.content) do
        if item.type == "text" then
          text = text .. item.text
        end
      end
    end

    if text == "" then
      vim.notify("Symaira: Empty entry: " .. path, vim.log.levels.WARN)
      return
    end

    local ok, parsed = pcall(vim.json.decode, text)
    if ok and parsed and parsed.data and parsed.data.password then
      local pw = parsed.data.password
      if type(pw) == "string" then
        vim.api.nvim_put({ pw }, "c", true, true)
        vim.notify("Symaira: Password inserted for " .. path, vim.log.levels.INFO)
        return
      end
    end

    vim.notify("Symaira: No password field in entry " .. path, vim.log.levels.WARN)
  end)
end

--- Copy an entry's password to clipboard via MCP tool.
---@param path string
function M.copy_to_clipboard(path)
  client.call_tool("copy_to_clipboard", { path = path }, function(err)
    if err then
      vim.notify("Symaira: " .. err, vim.log.levels.ERROR)
      return
    end
    vim.notify("Symaira: Copied " .. path .. " to clipboard", vim.log.levels.INFO)
  end)
end

--- Generate a password and insert at cursor.
---@param length integer
function M.generate_password(length)
  client.call_tool("generate_password", { length = length, symbols = true }, function(err, result)
    if err then
      vim.notify("Symaira: " .. err, vim.log.levels.ERROR)
      return
    end

    local text = ""
    if result and result.content then
      for _, item in ipairs(result.content) do
        if item.type == "text" then
          text = text .. item.text
        end
      end
    end

    if text == "" then
      vim.notify("Symaira: Failed to generate password", vim.log.levels.ERROR)
      return
    end

    local password = vim.trim(text)
    vim.api.nvim_put({ password }, "c", true, true)
    vim.notify("Symaira: Password generated (" .. #password .. " chars)", vim.log.levels.INFO)
  end)
end

--- Search entries by query and show results in a picker.
---@param query string
function M.find_entries(query)
  client.call_tool("find_entries", { query = query }, function(err, result)
    if err then
      vim.notify("Symaira: " .. err, vim.log.levels.ERROR)
      return
    end

    local text = ""
    if result and result.content then
      for _, item in ipairs(result.content) do
        if item.type == "text" then
          text = text .. item.text .. "\n"
        end
      end
    end

    if text == "" then
      vim.notify("Symaira: No results for '" .. query .. "'", vim.log.levels.WARN)
      return
    end

    local ok, parsed = pcall(vim.json.decode, text)
    local entry_list = {}
    if ok and type(parsed) == "table" then
      if parsed.entries and type(parsed.entries) == "table" then
        entry_list = parsed.entries
      elseif vim.tbl_islist(parsed) then
        entry_list = parsed
      end
    end

    if #entry_list == 0 then
      vim.notify("Symaira: No results for '" .. query .. "'", vim.log.levels.WARN)
      return
    end

    local entries = {}
    for _, entry in ipairs(entry_list) do
      local display = entry.path or entry.name or "unknown"
      table.insert(entries, display)
    end

    vim.ui.select(entries, {
      prompt = "Symaira Search: " .. query,
      format_item = function(item)
        return item
      end,
    }, function(choice)
      if not choice then
        return
      end
      picker.show_entry_detail(choice)
    end)
  end)
end

--- Generate TOTP for an entry.
---@param path string
function M.generate_totp(path)
  client.call_tool("generate_totp", { path = path }, function(err, result)
    if err then
      vim.notify("Symaira: " .. err, vim.log.levels.ERROR)
      return
    end

    local text = ""
    if result and result.content then
      for _, item in ipairs(result.content) do
        if item.type == "text" then
          text = text .. item.text
        end
      end
    end

    if text == "" then
      vim.notify("Symaira: No TOTP for " .. path, vim.log.levels.WARN)
      return
    end

    local totp_code = vim.trim(text)
    vim.api.nvim_put({ totp_code }, "c", true, true)
    vim.notify("Symaira: TOTP inserted for " .. path, vim.log.levels.INFO)
  end)
end

return M
