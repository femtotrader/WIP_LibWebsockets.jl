module LibWebsockets

using Serde

__precompile__(false)

#include("../lib/wrapper.jl")

using libwebsockets_jll
export libwebsockets_jll

function lws_get_library_version()
    @ccall libwebsockets.lws_get_library_version()::Ptr{Cchar}
end

function version()
    ptr = lws_get_library_version()
    unsafe_string(ptr)
end

include("types.jl")
include("constants.jl")
include("errors.jl")
include("common.jl")
#include("wrapper.jl")
include("client.jl")
include("server.jl")

export open, send, recv, isopen

end # module
