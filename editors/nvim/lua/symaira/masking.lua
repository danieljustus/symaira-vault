local config = require("symvault.config")

local M = {}

--- Mask a single value, showing only mask characters.
---@param value string
---@return string
function M.mask_value(value)
  if not value or value == "" then
    return ""
  end
  local mask_char = config.get("masking_char")
  return string.rep(mask_char, 3)
end

--- Check if a key should be preserved (not masked).
---@param key string
---@return boolean
local function is_preserved(key)
  local preserved = config.get("preserve_keys")
  for _, k in ipairs(preserved) do
    if k == key then
      return true
    end
  end
  return false
end

--- Recursively mask all string values in a table while preserving structure.
--- Non-string values (numbers, booleans, nil) are kept as-is.
--- Keys in preserve_keys are left unmasked.
---@param obj table
---@return table
function M.mask_object(obj)
  if type(obj) ~= "table" then
    return obj
  end
  local result = {}
  for k, v in pairs(obj) do
    if is_preserved(k) then
      result[k] = v
    elseif type(v) == "string" then
      result[k] = M.mask_value(v)
    elseif type(v) == "table" then
      result[k] = M.mask_object(v)
    else
      result[k] = v
    end
  end
  return result
end

--- Mask an entry's data fields while preserving path and metadata.
---@param entry table Entry with path, data, and meta fields.
---@return table Masked copy of the entry.
function M.mask_entry(entry)
  if not entry then
    return nil
  end
  local masked = {}
  masked.path = entry.path
  masked.data = M.mask_object(entry.data or {})
  masked.meta = entry.meta
  return masked
end

return M
