using Test
using LibWebsockets

@testset "LibWebsockets.jl" begin
    include("common_tests.jl")
    include("client_tests.jl")
    include("server_tests.jl")
    include("wrapper_tests.jl")
end
