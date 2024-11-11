using Test
using LibWebsockets:
    WSClient, WSClientData, create_ws_client, send_message, service, LibWebsocketsError
using LibWebsockets.LibWebsocketsWrapper: lws

@testset "client_tests" begin
    @testset "client creation" begin
        client = nothing

        @test_nowarn client = WSClient()
        @test client isa WSClient
        @test isempty(client.protocols)
        @test client.data.need_to_send == false
        @test client.data.pending_message == ""
    end

    @testset "error handling" begin
        # Test invalid URLs
        @test_throws ArgumentError create_ws_client("")
        @test_throws ArgumentError create_ws_client("invalid")
        @test_throws ArgumentError create_ws_client("http://")

        # Test with a not connected client
        client = WSClient()
        @test !isopen(client)
        @test_throws LibWebsocketsError send_message(client, "test")

        # Test with a badly initialized client
        bad_client = WSClient()
        bad_client.wsi = Ptr{lws}(1)  # invalid pointer
        @test !isopen(bad_client)
        @test_throws LibWebsocketsError send_message(bad_client, "test")
    end

    @testset "echo server connection" begin
        message_received = Ref(false)
        connection_established = Ref(false)
        error_occurred = Ref(false)
        received_message = Ref("")

        try
            client = create_ws_client(
                "wss://echo.websocket.org",
                skip_cert_verify=true,  # only for testing purpose
                on_message = msg -> begin
                    message_received[] = true
                    received_message[] = msg
                end,
                on_connected = () -> (connection_established[] = true),
                on_error = err -> (error_occurred[] = true),
            )

            timeout = time() + 5
            while !connection_established[] && time() < timeout
                service(client.context, 50)
                sleep(0.1)
            end

            if connection_established[]
                test_message = "Test message"
                send_message(client, test_message)

                timeout = time() + 5
                while !message_received[] && time() < timeout
                    service(client.context, 50)
                    sleep(0.1)
                end

                @test message_received[]
                @test received_message[] == test_message
                @test !error_occurred[]

                close(client)
                @test !isopen(client)
            else
                @info "Failed to connect to echo server - skipping echo tests"
            end
        catch e
            @info "Echo server test failed" exception = e
            rethrow()
        end
    end
end
