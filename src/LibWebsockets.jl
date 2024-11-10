module LibWebsockets

using Serde

include("../lib/wrapper.jl")

using libwebsockets_jll
export libwebsockets_jll

include("context.jl")
include("types.jl")
include("constants.jl")
include("errors.jl")
include("common.jl")
include("client.jl")
include("server.jl")

export open, send, recv, isopen

end # module
