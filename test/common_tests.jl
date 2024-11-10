using LibWebsockets: version


@testset "common_tests" begin
  @test version() == v"4.3.3-v4.3.3"
end
