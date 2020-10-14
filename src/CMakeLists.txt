file(GLOB_RECURSE Virtlyst_SRCS *.cpp *.h lib/*.cpp lib/*.h)

set(Virtlyst_SRCS
    ${Virtlyst_SRCS}
    ${TEMPLATES_SRC}
)

# Create the application
add_library(Virtlyst SHARED ${Virtlyst_SRCS})

# Link to Cutelyst
target_link_libraries(Virtlyst
    Cutelyst::Core
    Cutelyst::View::Cutelee
    Cutelyst::Utils::Sql
    Cutelyst::Authentication
    Cutelyst::StatusMessage
    Cutelyst::Session
    Cutelee5::Templates
    Cutelyst::CSRFProtection
    Qt5::Core
    Qt5::Network
    Qt5::Sql
    Qt5::Xml
    ${LIBVIRT_LIBRARIES}
    ${LIBSSH_LIBRARIES}
)

install(TARGETS Virtlyst DESTINATION Virtlyst )
