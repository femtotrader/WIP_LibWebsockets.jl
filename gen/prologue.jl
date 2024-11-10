# gen/prologue.jl
# Basic types for VFS
const lws_filefd_type = Int32
const lws_fop_flags_t = UInt32
const lws_filepos_t = UInt64
const lws_fileofs_t = Int64

# Constants needed for FreeRTOS
const LWS_FOP_READ = :read
const LWS_FOP_WRITE = :write
const LWS_FOP_OPEN = :open
const LWS_FOP_CLOSE = :close
const LWS_FOP_SEEK_CUR = :seek_cur
