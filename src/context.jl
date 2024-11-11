"""
    version()

Get version number of lws library
"""
function version()
    ptr = LibWebsocketsWrapper.lws_get_library_version()
    VersionNumber(unsafe_string(ptr))
end
