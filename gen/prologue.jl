# prologue.jl

# Type definitions for standard C types
const uint64_t = UInt64
const uint32_t = UInt32
const uint16_t = UInt16
const uint8_t = UInt8
const int64_t = Int64
const int32_t = Int32
const int16_t = Int16
const int8_t = Int8

const intptr_t = Ptr{Cvoid} isa Ptr{Int64} ? Int64 : Int32

# Standard POSIX file access constants
const O_RDONLY = Base.Filesystem.JL_O_RDONLY    # Read only
const O_WRONLY = Base.Filesystem.JL_O_WRONLY    # Write only
const O_RDWR = Base.Filesystem.JL_O_RDWR        # Read and write
const O_APPEND = Base.Filesystem.JL_O_APPEND    # Append mode
const O_CREAT = Base.Filesystem.JL_O_CREAT      # Create file if it doesn't exist
const O_TRUNC = Base.Filesystem.JL_O_TRUNC      # Truncate file

# Basic types for VFS
const lws_filefd_type = Int32
const lws_fop_flags_t = UInt32
const lws_filepos_t = UInt64
const lws_fileofs_t = Int64

const LWS_FOP_READ = :read
const LWS_FOP_WRITE = :write
const LWS_FOP_OPEN = :open
const LWS_FOP_CLOSE = :close
const LWS_FOP_SEEK_CUR = :seek_cur

#struct lws_xos
#    s::NTuple{4, UInt64}
#end

function lws_xos(xos)
    @ccall libwebsockets.lws_xos(xos::Ptr{lws_xos})::UInt64
end

# Manual definition of some constants
const LWS_PRE = 16
const LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT = 0x00000001
const LCCSCF_USE_SSL = 0x0200
const LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK = 0x0800
