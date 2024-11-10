using LibWebsockets: lws_get_library_version


@testset "common_tests" begin
  println(lws_get_library_version())
  @test 1 == 2
end
