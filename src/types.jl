using ..LibWebsocketsWrapper: lws, lws_context

"""
   WSClientData()

Client data structure
"""
mutable struct WSClientData
    need_to_send::Bool
    pending_message::String

    WSClientData() = new(false, "")
end

"""
    WSClient(;
        on_message::Function = (msg) -> nothing,
        on_connected::Function = () -> nothing,
        on_error::Function = (err) -> nothing,
    )

WebSocket client type encapsulating the connection state
"""
mutable struct WSClient
    context::Ptr{lws_context}
    wsi::Ptr{lws}
    protocols::Vector{lws_protocols}
    on_message::Function
    on_connected::Function
    on_error::Function
    data::WSClientData

    function WSClient(;
        on_message::Function = (msg) -> nothing,
        on_connected::Function = () -> nothing,
        on_error::Function = (err) -> nothing,
    )
        new(C_NULL, C_NULL, [], on_message, on_connected, on_error, WSClientData())
    end
end

export WSClient, WSClientData
