module LibWebsockets

using Serde

__precompile__(false)

include("../lib/wrapper.jl")

__precompile__(true)

using libwebsockets_jll
export libwebsockets_jll

function version()
    ptr = LibWebsocketsWrapper.lws_get_library_version()
    VersionNumber(unsafe_string(ptr))
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
