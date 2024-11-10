module LibWebsockets

using Serde

__precompile__(false)

include("../lib/wrapper.jl")

include("types.jl")
include("constants.jl")
include("errors.jl")
include("common.jl")
include("wrapper.jl")
include("client.jl")
include("server.jl")

export open, send, recv, isopen

end # module
