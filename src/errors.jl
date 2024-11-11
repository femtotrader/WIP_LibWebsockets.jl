# errors.jl
struct LibWebsocketsError <: Exception
    msg::String
end
