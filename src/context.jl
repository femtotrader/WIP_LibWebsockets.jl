function version()
    ptr = LibWebsocketsWrapper.lws_get_library_version()
    VersionNumber(unsafe_string(ptr))
end