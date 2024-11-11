using LibWebsockets

const WEBSOCKET_URL = "wss://ws.postman-echo.com/raw"
const DEFAULT_TIMEOUT = 5  # 5 seconds timeout

mutable struct WSClientState
    connected::Bool
    message_received::Bool
    error_occurred::Bool
    error_message::String
    should_stop::Bool

    WSClientState() = new(false, false, false, "", false)
end

function wait_for_condition(client, state::WSClientState, check_fn::Function; timeout_seconds=DEFAULT_TIMEOUT)
    start_time = time()
    while !state.should_stop && !check_fn(state) && (time() - start_time) < timeout_seconds
        try
            @info "in the loop"
            service(client.context, 50)
            sleep(0.1)
        catch e
            println("An exception occured - $e")
            state.error_occurred = true
            state.error_message = string(e)
            state.should_stop = true
            return false
        end
    end
    return check_fn(state)
end

function run_echo_test()
    state = WSClientState()

    # Create WebSocket client with proper error handling
    client = create_ws_client(
        WEBSOCKET_URL,
        skip_cert_verify=true,
        on_message = msg -> begin
            @info "Received: $msg"
            state.message_received = true
        end,
        on_connected = () -> begin
            @info "Connected!"
            state.connected = true
        end,
        on_error = err -> begin
            @error "Error: $err"
            state.error_occurred = true
            state.error_message = string(err)
            state.should_stop = true
        end
    )

    try
        @info "Waiting for connection..."
        connection_success = wait_for_condition(client, state, s -> s.connected)
        
        if connection_success
            @info "Sending message..."
            send_message(client, "Hello WebSocket!")
            
            @info "Waiting for response..."
            message_received = wait_for_condition(client, state, s -> s.message_received)
            
            if !message_received
                @warn "No response received within timeout"
            end
        else
            if state.error_occurred
                @error "Connection failed: $(state.error_message)"
            else
                @error "Connection timeout"
            end
        end

    catch e
        @error "Unexpected error: $e"
    finally
        # Always cleanup
        if client !== nothing
            close(client)
            @info "Connection closed"
        end
    end
end

# Run the test
run_echo_test()