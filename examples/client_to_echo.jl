using LibWebsockets

client = create_ws_client(
    "wss://echo.websocket.org",
    on_message = msg -> println("Received: $msg"),
    on_connected = () -> println("Connected!"),
    on_error = err -> println("Error: $err"),
)

send_message(client, "Hello WebSocket!")

while isopen(client)
    service(client.context, 50)
end

close(client)
