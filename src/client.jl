# client.jl

import Base: isopen, close
using URIs

"""
WebSocket client implementation
"""
const WS_CLIENTS = Dict{Ptr{lws},WSClient}()

"""
    ws_callback(wsi::Ptr{lws}, reason::Cuint, user::Ptr{Cvoid}, in_data::Ptr{Cvoid}, len::Csize_t)::Cint

Generic callback handler for WebSocket events
"""
function ws_callback(
    wsi::Ptr{lws},
    reason::Cuint,
    user::Ptr{Cvoid},
    in_data::Ptr{Cvoid},
    len::Csize_t,
)::Cint

    client = get(WS_CLIENTS, wsi, nothing)
    isnothing(client) && return 0

    if reason == LWS_CALLBACK_CLIENT_ESTABLISHED
        client.on_connected()

    elseif reason == LWS_CALLBACK_CLIENT_RECEIVE
        message = unsafe_string(Ptr{Cchar}(in_data), len)
        client.on_message(message)

    elseif reason == LWS_CALLBACK_CLIENT_WRITEABLE
        if client.data.need_to_send
            msg_len = length(client.data.pending_message)
            buf = Vector{UInt8}(undef, LWS_PRE + msg_len)

            unsafe_copyto!(
                pointer(buf) + LWS_PRE,
                pointer(Vector{UInt8}(client.data.pending_message)),
                msg_len,
            )

            n = lws_write(wsi, pointer(buf) + LWS_PRE, msg_len, LWS_WRITE_TEXT)

            if n < 0
                client.on_error("Send error")
                return -1
            end

            client.data.need_to_send = false
        end

    elseif reason == LWS_CALLBACK_CLIENT_CONNECTION_ERROR
        error_msg =
            isnothing(in_data) ? "Connection error" : unsafe_string(Ptr{Cchar}(in_data))
        client.on_error(error_msg)

    elseif reason == LWS_CALLBACK_CLOSED
        delete!(WS_CLIENTS, wsi)
        client.on_error("Connection closed")
    end

    return 0
end

"""
    create_protocols()

Create WebSocket protocols for the client
"""
function create_protocols()
    callback_c =
        @cfunction(ws_callback, Cint, (Ptr{lws}, Cuint, Ptr{Cvoid}, Ptr{Cvoid}, Csize_t))

    [
        lws_protocols(
            pointer("ws-protocol"),
            callback_c,
            sizeof(WSClientData),
            0,
            0,
            C_NULL,
            0,
        ),
        lws_protocols(C_NULL, C_NULL, 0, 0, 0, C_NULL, 0),
    ]
end

"""
    create_context_info(protocols::Vector{lws_protocols})::lws_context_creation_info

Create a new lws_context_creation_info with default values
"""
function create_context_info(protocols::Vector{lws_protocols})::lws_context_creation_info
    lws_context_creation_info(
        convert(Ptr{Int8}, C_NULL),     # iface
        pointer(protocols),              # protocols
        convert(Ptr{lws_extension}, C_NULL),  # extensions
        convert(Ptr{lws_token_limits}, C_NULL),  # token_limits
        convert(Ptr{Int8}, C_NULL),      # http_proxy_address
        convert(Ptr{lws_protocol_vhost_options}, C_NULL),  # headers
        convert(Ptr{lws_protocol_vhost_options}, C_NULL),  # reject_service_keywords
        convert(Ptr{lws_protocol_vhost_options}, C_NULL),  # pvo
        convert(Ptr{Int8}, C_NULL),      # log_filepath
        convert(Ptr{lws_http_mount}, C_NULL),  # mounts
        convert(Ptr{Int8}, C_NULL),      # server_string
        convert(Ptr{Int8}, C_NULL),      # error_document_404
        Int32(-1),                       # port
        UInt32(0),                       # http_proxy_port
        UInt32(0),                       # max_http_header_data2
        UInt32(0),                       # max_http_header_pool2
        Int32(0),                        # keepalive_timeout
        ntuple(i -> UInt32(0), 7),        # http2_settings
        UInt16(0),                       # max_http_header_data
        UInt16(0),                       # max_http_header_pool
        convert(Ptr{Int8}, C_NULL),      # ssl_private_key_password
        convert(Ptr{Int8}, C_NULL),      # ssl_cert_filepath
        convert(Ptr{Int8}, C_NULL),      # ssl_private_key_filepath
        convert(Ptr{Int8}, C_NULL),      # ssl_ca_filepath
        convert(Ptr{Int8}, C_NULL),      # ssl_cipher_list
        convert(Ptr{Int8}, C_NULL),      # ecdh_curve
        convert(Ptr{Int8}, C_NULL),      # tls1_3_plus_cipher_list
        Ptr{Cvoid}(C_NULL),              # server_ssl_cert_mem
        Ptr{Cvoid}(C_NULL),              # server_ssl_private_key_mem
        Ptr{Cvoid}(C_NULL),              # server_ssl_ca_mem
        Int64(0),                        # ssl_options_set
        Int64(0),                        # ssl_options_clear
        Int32(0),                        # simultaneous_ssl_restriction
        Int32(0),                        # simultaneous_ssl_handshake_restriction
        Int32(0),                        # ssl_info_event_mask
        UInt32(0),                       # server_ssl_cert_mem_len
        UInt32(0),                       # server_ssl_private_key_mem_len
        UInt32(0),                       # server_ssl_ca_mem_len
        convert(Ptr{Int8}, C_NULL),      # alpn
        convert(Ptr{Int8}, C_NULL),      # client_ssl_private_key_password
        convert(Ptr{Int8}, C_NULL),      # client_ssl_cert_filepath
        Ptr{Cvoid}(C_NULL),              # client_ssl_cert_mem
        UInt32(0),                       # client_ssl_cert_mem_len
        convert(Ptr{Int8}, C_NULL),      # client_ssl_private_key_filepath
        Ptr{Cvoid}(C_NULL),              # client_ssl_key_mem
        convert(Ptr{Int8}, C_NULL),      # client_ssl_ca_filepath
        Ptr{Cvoid}(C_NULL),              # client_ssl_ca_mem
        convert(Ptr{Int8}, C_NULL),      # client_ssl_cipher_list
        convert(Ptr{Int8}, C_NULL),      # client_tls_1_3_plus_cipher_list
        Int64(0),                        # ssl_client_options_set
        Int64(0),                        # ssl_client_options_clear
        UInt32(0),                       # client_ssl_ca_mem_len
        UInt32(0),                       # client_ssl_key_mem_len
        convert(Ptr{ssl_ctx_st}, C_NULL),# provided_client_ssl_ctx
        Int32(0),                        # ka_time
        Int32(0),                        # ka_probes
        Int32(0),                        # ka_interval
        UInt32(0),                       # timeout_secs
        UInt32(0),                       # connect_timeout_secs
        Int32(0),                        # bind_iface
        UInt32(0),                       # timeout_secs_ah_idle
        UInt32(0),                       # tls_session_timeout
        UInt32(0),                       # tls_session_cache_max
        typemax(UInt32),                 # gid
        typemax(UInt32),                 # uid
        UInt64(LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT),  # options
        Ptr{Cvoid}(C_NULL),              # user
        UInt32(1),                       # count_threads
        UInt32(0),                       # fd_limit_per_thread
        convert(Ptr{Int8}, C_NULL),      # vhost_name
        Ptr{Cvoid}(C_NULL),              # external_baggage_free_on_destroy
        UInt32(0),                       # pt_serv_buf_size
        convert(Ptr{lws_plat_file_ops}, C_NULL),  # fops
        convert(Ptr{Ptr{Cvoid}}, C_NULL), # foreign_loops
        Ptr{Cvoid}(C_NULL),              # signal_cb
        convert(Ptr{Ptr{lws_context}}, C_NULL),  # pcontext
        Ptr{Cvoid}(C_NULL),              # finalize
        Ptr{Cvoid}(C_NULL),              # finalize_arg
        convert(Ptr{Int8}, C_NULL),      # listen_accept_role
        convert(Ptr{Int8}, C_NULL),      # listen_accept_protocol
        convert(Ptr{Ptr{lws_protocols}}, C_NULL),  # pprotocols
        convert(Ptr{Int8}, C_NULL),      # username
        convert(Ptr{Int8}, C_NULL),      # groupname
        convert(Ptr{Int8}, C_NULL),      # unix_socket_perms
        convert(Ptr{lws_system_ops}, C_NULL),  # system_ops
        convert(Ptr{lws_retry_bo}, C_NULL),  # retry_and_idle_policy
        convert(Ptr{Ptr{lws_state_notify_link}}, C_NULL),  # register_notifier_list
        Int32(0),                        # rlimit_nofile
        Ptr{Cvoid}(C_NULL),              # early_smd_cb
        Ptr{Cvoid}(C_NULL),              # early_smd_opaque
        UInt32(0),                       # early_smd_class_filter
        Int64(0),                        # smd_ttl_us
        UInt16(0),                       # smd_queue_depth
        Int32(0),                        # fo_listen_queue
        convert(Ptr{lws_plugin_evlib}, C_NULL),  # event_lib_custom
        convert(Ptr{lws_log_cx}, C_NULL),  # log_cx
        convert(Ptr{Int8}, C_NULL),      # http_nsc_filepath
        Csize_t(0),                      # http_nsc_heap_max_footprint
        Csize_t(0),                      # http_nsc_heap_max_items
        Csize_t(0),                      # http_nsc_heap_max_payload
        (Ptr{Cvoid}(C_NULL), Ptr{Cvoid}(C_NULL)),  # _unused
    )
end

"""
    validate_ws_url(url::AbstractString)

Validate WebSocket URL
"""
function validate_ws_url(url::AbstractString)
    try
        uri = URI(url)
        if isnothing(uri.host) || isempty(uri.host)
            throw(ArgumentError("Invalid WebSocket URL: no host specified"))
        end
        if !(uri.scheme in ("ws", "wss", "http", "https"))
            throw(
                ArgumentError(
                    "Invalid WebSocket URL: scheme must be ws, wss, http, or https",
                ),
            )
        end
        return uri
    catch e
        if e isa ArgumentError
            rethrow()
        end
        throw(ArgumentError("Invalid WebSocket URL: unable to parse"))
    end
end

"""
    create_ws_client(url::AbstractString; use_ssl::Bool = true, on_message::Function = (msg) -> nothing, on_connected::Function = () -> nothing, on_error::Function = (err) -> nothing)::WSClient

Create a WebSocket client
"""
function create_ws_client(
    url::AbstractString;
    use_ssl::Bool = true,
    on_message::Function = (msg) -> nothing,
    on_connected::Function = () -> nothing,
    on_error::Function = (err) -> nothing,
)::WSClient

    # Validate URL first
    uri = validate_ws_url(url)
    client =
        WSClient(on_message = on_message, on_connected = on_connected, on_error = on_error)
    client.protocols = create_protocols()

    # Create context avec le maximum pour uid/gid
    info = Ref(
        lws_context_creation_info(
            C_NULL,
            pointer(client.protocols),
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            CONTEXT_PORT_NO_LISTEN,
            0,
            0,
            0,
            0,
            ntuple(i -> UInt32(0), 7),
            0,
            0,
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            0,
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            0,
            0,
            0,
            0,
            C_NULL,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            typemax(UInt32),
            typemax(UInt32),
            UInt32(LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT),
            C_NULL,
            1,
            0,
            C_NULL,
            C_NULL,
            0,
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            0,
            C_NULL,
            C_NULL,
            0,
            0,
            0,
            0,
            C_NULL,
            C_NULL,
            C_NULL,
            0,
            0,
            0,
            (C_NULL, C_NULL),
        ),
    )

    client.context = lws_create_context(info)
    isnothing(client.context) && throw(LibWebsocketsError("Failed to create context"))

    # Set up connection parameters
    host = string(uri.host)
    port = Int32(isnothing(uri.port) ? (use_ssl ? 443 : 80) : uri.port)
    path = isempty(uri.path) ? "/" : string(uri.path)

    # Create connection info avec la signature complète
    ccinfo = Ref(
        lws_client_connect_info(
            client.context,                # context
            Base.unsafe_convert(Ptr{Int8}, host),  # address
            port,                          # port
            Int32(use_ssl ? LCCSCF_USE_SSL | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK : 0),  # ssl_connection
            Base.unsafe_convert(Ptr{Int8}, path),  # path
            Base.unsafe_convert(Ptr{Int8}, host),  # host
            Base.unsafe_convert(Ptr{Int8}, host),  # origin
            Base.unsafe_convert(Ptr{Int8}, "ws-protocol"),  # protocol
            Int32(0),                      # ietf_version_or_minus_one
            C_NULL,                        # any_wsi
            C_NULL,                        # storage
            C_NULL,                        # http_auth_basic
            C_NULL,                        # parent_wsi
            C_NULL,                        # uri_replace_from
            C_NULL,                        # uri_replace_to
            Ptr{lws_vhost}(C_NULL),       # vhost
            C_NULL,                        # pwsi
            C_NULL,                        # initial_protocol_name
            C_NULL,                        # alpn
            C_NULL,                        # local_protocol_name
            C_NULL,                        # seq 
            C_NULL,                        # seq_info
            C_NULL,                        # retry_bo
            Int32(0),                      # fail_count
            UInt8(0),                      # priority
            UInt8(0),                      # ssl_connection_in
            C_NULL,                        # userdata
            C_NULL,                        # mux_substream
            UInt16(0),                     # _unused1
            C_NULL,                        # log_cx
            (C_NULL, C_NULL, C_NULL, C_NULL),  # _unused2
        ),
    )

    client.wsi = lws_client_connect_via_info(ccinfo)
    isnothing(client.wsi) && throw(LibWebsocketsError("Failed to create connection"))

    WS_CLIENTS[client.wsi] = client
    return client
end


"""
    send_message(client::WSClient, message::AbstractString)

Send a message through the WebSocket connection
"""
function send_message(client::WSClient, message::AbstractString)
    if !isopen(client) || client.wsi === C_NULL || !haskey(WS_CLIENTS, client.wsi)
        throw(LibWebsocketsError("Connection not open"))
    end

    client.data.pending_message = message
    client.data.need_to_send = true
    rc = lws_callback_on_writable(client.wsi)
    if rc < 0
        throw(LibWebsocketsError("Failed to schedule write"))
    end
end

"""
    isopen(client::WSClient)::Bool

Check if the WebSocket connection is open
"""
function isopen(client::WSClient)::Bool
    client.context !== C_NULL && client.wsi !== C_NULL && haskey(WS_CLIENTS, client.wsi)
end

"""
    close(client::WSClient)

Close the WebSocket connection
"""
function close(client::WSClient)
    if client.wsi !== C_NULL && haskey(WS_CLIENTS, client.wsi)
        delete!(WS_CLIENTS, client.wsi)
    end
    if client.context !== C_NULL
        lws_context_destroy(client.context)
    end
    client.context = C_NULL
    client.wsi = C_NULL
end

"""
    service(context::Ptr{lws_context}, timeout::Integer)

Service WebSocket events with the specified timeout.
"""
function service(context::Ptr{lws_context}, timeout::Integer)
    lws_service(context, timeout)
end

# Exports
export open, send_message, service
