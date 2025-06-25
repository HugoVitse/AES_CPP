cmake_minimum_required(VERSION 3.19)
project(aes_cpp_ui LANGUAGES CXX)

find_package(Qt6 6.5 REQUIRED COMPONENTS Core Widgets)


qt_standard_project_setup()

qt_add_executable(aes_cpp_ui
    WIN32 MACOSX_BUNDLE
    main.cpp
    mainwindow.cpp
    mainwindow.h
    mainwindow.ui
    encryptedfileregistry.h encryptedfileregistry.cpp
)

target_link_libraries(aes_cpp_ui
    PRIVATE
        Qt::Core
        Qt::Widgets
        aes_lib
)

include(GNUInstallDirs)

if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
    target_link_libraries(aes_cpp_ui PRIVATE aes_lib Boost::program_options)
else()
    message(FATAL_ERROR "Boost not found")
endif()

install(TARGETS aes_cpp_ui
    BUNDLE  DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

qt_generate_deploy_app_script(
    TARGET aes_cpp_ui
    OUTPUT_SCRIPT deploy_script
    NO_UNSUPPORTED_PLATFORM_ERROR
)
install(SCRIPT ${deploy_script})
