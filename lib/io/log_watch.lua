local util = require("lib.core.util")

local watch = {}

function watch.new(path, read_from_start)
  local inode, size = util.stat_inode_size(path)
  return {
    path = path,
    inode = inode,
    offset = read_from_start and 0 or (size or 0),
  }
end

function watch.poll(w)
  local inode, size = util.stat_inode_size(w.path)
  if not inode then
    return {}
  end

  if w.inode and inode ~= w.inode then
    -- rotated or replaced
    w.inode = inode
    w.offset = 0
  end

  if not w.offset then w.offset = 0 end
  if size < w.offset then
    w.offset = 0
  end

  local f = io.open(w.path, "rb")
  if not f then return {} end
  f:seek("set", w.offset)
  local data = f:read("*a")
  local new_offset = f:seek("cur")
  f:close()

  w.offset = new_offset or w.offset
  return util.split_lines(data)
end

return watch
