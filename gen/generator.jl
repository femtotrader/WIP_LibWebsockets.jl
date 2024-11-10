using libwebsockets_jll
using OpenSSL_jll
using Clang
using Clang.Generators
using CEnum

const LIBWEBSOCKETS_LIB_PATH = libwebsockets_jll.artifact_dir
const LIBWEBSOCKETS_INCLUDE_PATH = joinpath(LIBWEBSOCKETS_LIB_PATH, "include")

const OPENSSL_LIB_PATH = OpenSSL_jll.artifact_dir
const OPENSSL_INCLUDE_PATH = joinpath(OPENSSL_LIB_PATH, "include")

# Types in dependency order
const TYPE_ORDER = [
    "lws",
    "lws_context",
    "lws_protocols",
    "lws_token_limits",
    "lws_dll2_owner",
    "lws_threadpool_task_status",
    "lws_tokenize",
    "lws_fops_index",
    "lws_plat_file_ops",
    "lws_fop_fd"
]

# Functions to wrap
const ESSENTIAL_FUNCTIONS = [
    "lws_create_context",
    "lws_context_destroy",
    "lws_service",
    "lws_write",
    "lws_callback_on_writable",
    "lws_get_library_version",
    "lws_get_fops",
    "lws_set_fops"
]

const ESSENTIAL_ENUMS = [
    "lws_callback_reasons",
    "lws_write_protocol",
    "lws_token_indexes"
]

const FIXABLE_EXPRS_TO_STR_CONCAT = [
    "OSSL_HTTP_PREFIX",
    "OSSL_HTTPS_PREFIX"
]

const FILTERED_PATTERNS = [
    "LWS_TI",
    "LWS_PI",
    "OSSL_DEPRECATEDIN",
    "OSSL_DEPRECATEDIN_3_0",
    "OSSL_DEPRECATED",
    "OPENSSL_FILE",
    "OPENSSL_LINE",
    "ossl_ssize_t",
    "OSSL_SSIZE_MAX",
    "CRYPTO_ONCE_STATIC_INIT",
    "ossl_bio__attr__",
    "ossl_bio__printf__",
    "OSSL_PARAM_UNMODIFIED",
    "OSSL_PARAM_END",
    "EVP_CIPH_FLAG_PIPELINE",
    "EVP_MD_CTX_size",
    "EVP_MD_CTX_block_size",
    "EVP_MD_CTX_type",
    "EVP_CIPHER_CTX_type",
    "EVP_CIPHER_CTX_mode",
    "TLS_DEFAULT_CIPHERSUITES",
    "SSL_OP_NO_EXTENDED_MASTER_SECRET",
    "SSL_OP_CLEANSE_PLAINTEXT",
    "SSL_OP_LEGACY_SERVER_CONNECT",
    "SSL_OP_ENABLE_KTLS",
    "SSL_OP_TLSEXT_PADDING",
    "SSL_OP_SAFARI_ECDHE_ECDSA_BUG",
    "SSL_OP_IGNORE_UNEXPECTED_EOF",
    "SSL_OP_ALLOW_CLIENT_RENEGOTIATION",
    "SSL_OP_DISABLE_TLSEXT_CA_NAMES",
    "SSL_OP_ALLOW_NO_DHE_KEX",
    "SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS",
    "SSL_OP_NO_QUERY_MTU",
    "SSL_OP_COOKIE_EXCHANGE",
    "SSL_OP_NO_TICKET",
    "SSL_OP_CISCO_ANYCONNECT",
    "SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION",
    "SSL_OP_NO_COMPRESSION",
    "SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION",
    "SSL_OP_NO_ENCRYPT_THEN_MAC",
    "SSL_OP_ENABLE_MIDDLEBOX_COMPAT",
    "SSL_OP_PRIORITIZE_CHACHA",
    "SSL_OP_CIPHER_SERVER_PREFERENCE",
    "SSL_OP_TLS_ROLLBACK_BUG",
    "SSL_OP_NO_ANTI_REPLAY",
    "SSL_OP_NO_SSLv3",
    "SSL_OP_NO_TLSv1",
    "SSL_OP_NO_TLSv1_2",
    "SSL_OP_NO_TLSv1_1",
    "SSL_OP_NO_TLSv1_3",
    "SSL_OP_NO_DTLSv1",
    "SSL_OP_NO_DTLSv1_2",
    "SSL_OP_NO_RENEGOTIATION",
    "SSL_OP_CRYPTOPRO_TLSEXT_BUG",
    "SSL_OP_NO_SSL_MASK",
    "SSL_OP_NO_DTLS_MASK",
    "SSL_OP_ALL",
    "SSL_get1_curves",
    "SSL_CTX_set1_curves",
    "SSL_CTX_set1_groups",
    "SSL_CTX_set1_curves_list",
    "SSL_set1_curves",
    "SSL_set1_curves_list",
    "SSL_get_shared_curve",
    "ERR_raise_data",
    "ERR_SYSTEM_FLAG",
    "ERR_SYSTEM_MASK",
    "ERR_REASON_MASK",
    "lws_pollfd",
    "LWS_POLLHUP",
    "LWS_POLLIN",
    "LWS_POLLOUT",
    "LWS_PROTOCOL_LIST_TERM",
    "LWS_ILLEGAL_HTTP_CONTENT_LEN",
    "LWS_SEND_BUFFER_PRE_PADDING",
    "LWS_PRE",
    "LWS_FOP_READ",
    "LWS_FOP_WRITE",
    "LWS_FOP_OPEN",
    "LWS_FOP_CLOSE",
    "LWS_FOP_SEEK_CUR",
    "lws_xos"
]


# List of functions to exclude from generation
# const EXCLUDE_FUNCTIONS = [
#    "OSSL_provider_init"
#]

# Handle struct/function name conflicts
const NAME_CONFLICTS = Dict{String,String}(
    "lws_dll2_owner" => "lws_dll2_owner_fn",
    "lws_threadpool_task_status" => "lws_threadpool_task_status_fn",
    "lws_tokenize" => "lws_tokenize_fn"
)

function rename_type(name::AbstractString)
    get(NAME_CONFLICTS, name, name)
end

function should_wrap(cursor)
    name = string(cursor)
    kind = Clang.LibClang.clang_getCursorKind(cursor)
    
    # Block all deprecation related definitions with more specific checks
    if kind == Clang.LibClang.CXCursor_MacroDefinition
        tokens = Clang.tokenize(cursor)
        if !isnothing(tokens)
            token_text = join([Clang.spelling(t) for t in tokens], " ")
            if contains(token_text, "OSSL_DEPRECATED") || contains(token_text, "OSSL_DEPRECATEDIN")
                @info "Skipping deprecation macro:" name token_text
                return false
            end
        end
    end
    
    # Filter out patterns from FILTERED_PATTERNS
    if any(pattern -> contains(name, pattern), FILTERED_PATTERNS)
        @info "Skipping filtered pattern:" name
        return false
    end
    
    if kind == Clang.LibClang.CXCursor_FunctionDecl
        return name in ESSENTIAL_FUNCTIONS || haskey(NAME_CONFLICTS, name)
    elseif kind in [Clang.LibClang.CXCursor_StructDecl, Clang.LibClang.CXCursor_TypedefDecl]
        # Respect the order of TYPE_ORDER
        for (index, type_name) in enumerate(TYPE_ORDER)
            if type_name == name
                @info "Found type $name at position $index"
                return true
            end
        end
        return false
    elseif kind == Clang.LibClang.CXCursor_EnumDecl ||
           kind == Clang.LibClang.CXCursor_EnumConstantDecl
        return true
    end
    
    false
end

function generate_wrapper()
    compile_defs = [
        "-DLWS_WITH_HTTP_UNCOMMON_HEADERS",
        "-DLWS_ROLE_H2",
        "-DLWS_HTTP_HEADERS_ALL",
        "-DLWS_ROLE_WS",
        "-DLWS_WITH_HTTP_UNCOMMON_HEADERS",
        "-DLWS_WITH_CUSTOM_HEADERS",
        "-DLWS_WITH_FILE_OPS",
        "-DLWS_WITH_VFS"
    ]

    options = Dict{String,Any}(
        "general" => Dict{String,Any}(
            "library_name" => "libwebsockets",
            "module_name" => "LibWebsocketsWrapper",
            "output_file_path" => "../lib/wrapper.jl",
            "jll_pkg_name" => "libwebsockets_jll",
            "prologue_file_path" => "./prologue.jl",
            "output_ignorelist" => FILTERED_PATTERNS
        ),
        "codegen" => Dict{String,Any}(
            "use_julia_bool" => true,
            "use_ccall_macro" => true,
            "wrap_structs" => true,
            "wrap_enums" => true,
            "struct_field_comment_style" => "doxygen",
            "enum_export_symbols" => true,
            "function_rename_transform" => rename_type,
            "exclude_structs" => [r"struct \(unnamed at.*\)"],
            #"exclude_defines" => FILTERED_PATTERNS,
            #"exclude_macros" => FILTERED_PATTERNS,
            #"ignore_header_defines" => FILTERED_PATTERNS,
            #"ignore_header_macros" => true
        )
    )
    
    # Headers in dependency order
    headers = [
        # joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "libwebsockets", "lws-logs.h"),
        # joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "libwebsockets", "lws-freertos.h"),
        # joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "libwebsockets", "lws-optee.h"),
        # joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "lws-dll2.h"),
        # joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "lws-map.h"),
        # joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "lws-fault-injection.h"),
        # joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "lws-backtrace.h"),
        # joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "lws-timeout-timer.h"),
        # joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "lws-cache-ttl.h"),
        # joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "lws-smd.h"),
        # joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "lws-state.h"),
        # joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "lws-retry.h"),
        # joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "lws-adopt.h"),
        # joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "lws-network-helper.h"),
        # joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "lws-metrics.h"),
        # joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "lws-ota.h"),
        # joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "lws-system.h"),
        # joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "lws-ws-close.h"),
        # joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "lws-callbacks.h"),
        # joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "lws-ws-state.h"),
        # joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "lws-ws-ext.h"),
        # joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "lws-protocols-plugins.h"),
        # joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "lws-context-vhost.h"),
        # joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "lws-conmon.h"),
        # joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "lws-mqtt.h"),
        # joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "libwebsockets", "lws-vfs.h"),
        # joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "libwebsockets", "lws-context-vhost.h"),
        # joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "libwebsockets", "lws-http.h"),
        joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "libwebsockets.h")
    ]
    
    args = get_default_args()
    push!(args, "-I$LIBWEBSOCKETS_INCLUDE_PATH")
    push!(args, "-I$OPENSSL_INCLUDE_PATH")

    append!(args, compile_defs)
    
    ctx = create_context(headers, args, options)
    #ctx.options["declaration_wrapped"] = should_wrap
    
    # build without printing so we can do custom rewriting
    build!(ctx, BUILDSTAGE_NO_PRINTING)

    # custom rewriter
    function rewrite_as_string_concatenation!(expr::Expr)
        if expr.head == :(=) && length(expr.args) == 2
            rhs = expr.args[2]
            if rhs isa Expr && rhs.head == :call && length(rhs.args) == 2
                # If it looks like string("://"), convert to string * "://"
                if rhs.args[1] isa String || (rhs.args[1] isa Symbol && string(rhs.args[1]) in ["OSSL_HTTP_NAME", "OSSL_HTTPS_NAME"])
                    @info "Converting string concat for:" expr
                    expr.args[2] = Expr(:call, :*, rhs.args[1], rhs.args[2])
                end
            end
        end
        return expr
    end

    function rewrite!(dag::ExprDAG)
        @info "Starting DAG rewrite"
        @info "Number of nodes:" length(get_nodes(dag))
        
        for node in get_nodes(dag)
            node_type = typeof(node)
            exprs = get_exprs(node)
                        
            # Dump to see exact structure
            for (i, expr) in enumerate(exprs)
                #@info "Expression $i:" expr
                if expr isa Expr 
                    if expr.head == :const
                        #@info "Found const expression:" expr.args[1]
                        const_expr = expr.args[1]
                        if const_expr isa Expr && const_expr.head == :(=)
                            lhs = const_expr.args[1]
                            lhs_str = string(lhs)
                            #@info "Checking LHS:" lhs_str                            
                            if lhs_str == "OSSL_HTTP_PREFIX" || lhs_str == "OSSL_HTTPS_PREFIX"
                                #@info "Found target expression:" lhs_str
                                rhs = const_expr.args[2]
                                if rhs isa Expr && rhs.head == :call
                                    #@info "Converting string concat for:" lhs_str
                                    const_expr.args[2] = Expr(:call, :*, rhs.args[1], rhs.args[2])
                                end
                            end
                        end
                    end
                end
            end
        end
    end

    rewrite!(ctx.dag)

    # print
    build!(ctx, BUILDSTAGE_PRINTING_ONLY)

end

generate_wrapper()
