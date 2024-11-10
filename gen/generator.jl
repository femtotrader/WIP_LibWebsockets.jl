using libwebsockets_jll
using Clang.Generators
using CEnum

const LIBWEBSOCKETS_LIB_PATH = libwebsockets_jll.artifact_dir
const LIBWEBSOCKETS_INCLUDE_PATH = joinpath(LIBWEBSOCKETS_LIB_PATH, "include")

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
            "prologue_file_path" => "./prologue.jl"
        ),
        "codegen" => Dict{String,Any}(
            "use_julia_bool" => true,
            "use_ccall_macro" => true,
            "wrap_structs" => true,
            "wrap_enums" => true,
            "struct_field_comment_style" => "doxygen",
            "enum_export_symbols" => true,
            "function_rename_transform" => rename_type
        )
    )
    
    # Headers in dependency order
    headers = [
        joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "libwebsockets", "lws-vfs.h"),
        joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "libwebsockets", "lws-context-vhost.h"),
        joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "libwebsockets", "lws-http.h"),
        joinpath(LIBWEBSOCKETS_INCLUDE_PATH, "libwebsockets.h")
    ]
    
    args = get_default_args()
    push!(args, "-I$LIBWEBSOCKETS_INCLUDE_PATH")
    append!(args, compile_defs)
    
    ctx = create_context(headers, args, options)
    ctx.options["declaration_wrapped"] = should_wrap
    
    build!(ctx)
end

generate_wrapper()
