using LibWebsockets


#const WEBSOCKET_URL = "wss://echo.websocket.org"
#const WEBSOCKET_URL = "wss://ws.ifelse.io"
const WEBSOCKET_URL = "wss://ws.postman-echo.com/raw"
#const WEBSOCKET_URL = "ws://websocket.org:80/echo/"

client = create_ws_client(
    WEBSOCKET_URL,
    skip_cert_verify=true,
    on_message = msg -> println("Received: $msg"),
    on_connected = () -> println("Connected!"),
    on_error = err -> println("Error: $err"),
)

send_message(client, "Hello WebSocket!")

while isopen(client)
    service(client.context, 50)
end

close(client)
