module LibWebsockets

using Serde
using URIs
using libwebsockets_jll

include("../lib/wrapper.jl")
using .LibWebsocketsWrapper:
    lws,
    lws_context,
    lws_protocols,
    lws_callback_function,
    lws_context_creation_info,
    lws_client_connect_info,
    lws_create_context,
    lws_client_connect_via_info,
    lws_service,
    lws_write,
    lws_callback_on_writable,
    lws_context_destroy,
    lws_wsi_user,
    lws_callback_reasons,
    lws_extension,
    lws_token_limits,
    lws_protocol_vhost_options,
    lws_http_mount,
    ssl_ctx_st,
    lws_retry_bo,
    lws_plat_file_ops,
    lws_system_ops,
    lws_state_notify_link,
    lws_plugin_evlib,
    lws_log_cx,
    lws_vhost,
    lws_sequencer,
    CONTEXT_PORT_NO_LISTEN,
    LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT,
    LCCSCF_USE_SSL,
    LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK,
    LWS_CALLBACK_CLIENT_ESTABLISHED,
    LWS_CALLBACK_CLIENT_RECEIVE,
    LWS_CALLBACK_CLIENT_WRITEABLE,
    LWS_CALLBACK_CLIENT_CONNECTION_ERROR,
    LWS_CALLBACK_CLOSED,
    LWS_SERVER_OPTION_PEER_CERT_NOT_REQUIRED,
    LCCSCF_ALLOW_SELFSIGNED,
    LCCSCF_ALLOW_EXPIRED

include("context.jl")
include("types.jl")
include("constants.jl")
include("errors.jl")
include("common.jl")
include("client.jl")
include("server.jl")

export WSClient, WSClientData, create_ws_client, send_message, service, LibWebsocketsError

end # module
