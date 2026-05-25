local client = require("symvault.client")
local masking = require("symvault.masking")

local M = {}

--- Open an interactive vault entry picker.
--- After selection, calls callback(entry_path) or shows entry details.
---@param opts table|nil Options: { prompt = string, on_select = function(path) }
function M.pick_vault_entry(opts)
  opts = opts or {}
  local prompt = opts.prompt or "Symaira Vault"

  client.call_tool("list_entries", { prefix = "" }, function(err, result)
    if err then
      vim.notify("Symaira: " .. err, vim.log.levels.ERROR)
      return
    end

    if not result or not result.content then
      vim.notify("Symaira: No entries found", vim.log.levels.WARN)
      return
    end

    local entries = {}
    local parsed
    for _, item in ipairs(result.content) do
      if item.type == "text" then
        local ok, decoded = pcall(vim.json.decode, item.text)
        if ok and type(decoded) == "table" then
          parsed = decoded
        end
      end
    end

    -- Determine entry list: result may be a flat array or wrapped in { entries = [...] }
    local entry_list = {}
    if parsed and type(parsed) == "table" then
      if parsed.entries and type(parsed.entries) == "table" then
        entry_list = parsed.entries
      elseif vim.tbl_islist(parsed) then
        entry_list = parsed
      end
    end

    if #entry_list == 0 then
      vim.notify("Symaira: No entries found", vim.log.levels.WARN)
      return
    end

    local display_items = {}
    for _, entry in ipairs(entry_list) do
      local masked = masking.mask_entry(entry)
      local display = masked.path or (entry.path or "unknown")
      table.insert(display_items, display)
      entries[display] = entry.path or entry.name or display
    end

    vim.ui.select(display_items, {
      prompt = prompt,
      format_item = function(item)
        return item
      end,
    }, function(choice)
      if not choice then
        return
      end
      local path = entries[choice]
      if path and opts.on_select then
        opts.on_select(path)
      elseif path then
        M.show_entry_detail(path)
      end
    end)
  end)
end

--- Show masked entry details in a floating window.
---@param path string Entry path.
function M.show_entry_detail(path)
  client.call_tool("get_entry", { path = path }, function(err, result)
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
      vim.notify("Symaira: Empty entry", vim.log.levels.WARN)
      return
    end

    -- Parse and mask the entry data
    local ok, parsed = pcall(vim.json.decode, text)
    local masked_text
    if ok and type(parsed) == "table" then
      local masked = masking.mask_entry(parsed)
      masked_text = vim.json.encode(masked)
    else
      masked_text = text
    end

    local buf = vim.api.nvim_create_buf(false, true)
    vim.api.nvim_buf_set_lines(buf, 0, -1, false, vim.split(masked_text, "\n"))
    vim.api.nvim_buf_set_option(buf, "modifiable", false)
    vim.api.nvim_buf_set_option(buf, "filetype", "json")

    local width = math.min(120, vim.o.columns - 4)
    local height = math.min(30, vim.o.lines - 4)
    local row = math.floor((vim.o.lines - height) / 2)
    local col = math.floor((vim.o.columns - width) / 2)

    local win_opts = {
      relative = "editor",
      width = width,
      height = height,
      row = row,
      col = col,
      style = "minimal",
      border = "rounded",
      title = " " .. path .. " ",
      title_pos = "center",
    }

    local win = vim.api.nvim_open_win(buf, true, win_opts)
    vim.keymap.set("n", "q", function()
      vim.api.nvim_win_close(win, true)
    end, { buffer = buf, nowait = true, silent = true })
  end)
end

return M
