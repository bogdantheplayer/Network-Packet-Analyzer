# Minimum CMake version required 
cmake_minimum_required(VERSION 3.16)
# Project name and language
project(PacketAnalyzer LANGUAGES CXX)

# Use C++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable Qt automatic MOC
set(CMAKE_AUTOMOC ON)
# Disable unused Qt auto tools
set(CMAKE_AUTOUIC OFF)
set(CMAKE_AUTORCC OFF)

# Find Qt6 libraries
# add Network for QHostInfo
find_package(Qt6 REQUIRED COMPONENTS Widgets Network)

# Define executable and source files
add_executable(PacketAnalyzer
  core/PacketInfo.h
  core/CaptureEngine.h core/CaptureEngine.cpp
  ui/MainWindow.h ui/MainWindow.cpp
  ui/main.cpp
  ui/PpsChart.h ui/PpsChart.cpp
)

# Link Qt libraries
target_link_libraries(PacketAnalyzer PRIVATE Qt6::Widgets Qt6::Network)


# Windows specific configuration
if (WIN32)
  # Ws2_32 is required for sockets
  target_link_libraries(PacketAnalyzer PRIVATE Ws2_32)

  # Npcap SDK
  set(NPCAP_SDK "E:/NpcapSDK")
  target_include_directories(PacketAnalyzer PRIVATE ${NPCAP_SDK}/Include)
  target_link_directories(PacketAnalyzer PRIVATE ${NPCAP_SDK}/Lib/x64)
  target_link_libraries(PacketAnalyzer PRIVATE wpcap Packet)
endif()
