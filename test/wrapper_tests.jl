using LibWebsockets.LibWebsocketsWrapper: lws_get_library_version


@testset "wrapper_tests" begin
    @testset "lws_get_library_version" begin
        @test unsafe_string(lws_get_library_version()) == "4.3.3-v4.3.3"
    end
end
