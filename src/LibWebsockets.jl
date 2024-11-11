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
    CONTEXT_PORT_NO_LISTEN,
    LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT,
    LCCSCF_USE_SSL,
    LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK

include("context.jl")
include("types.jl")
include("constants.jl")
include("errors.jl")
include("common.jl")
include("client.jl")
include("server.jl")

export WSClient, WSClientData, create_ws_client, send_message, service, LibWebsocketsError

end # module
