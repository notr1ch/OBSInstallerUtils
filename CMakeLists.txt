cmake_minimum_required(VERSION 3.10)
project(OBSInstallerUtils)

add_definitions(-DNOMINMAX -DUNICODE -D_UNICODE -D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_WARNINGS)
set(CMAKE_SHARED_LINKER_FLAGS_MINSIZEREL "${CMAKE_SHARED_LINKER_FLAGS_MINSIZEREL} /OPT:REF /SAFESEH:NO /INCREMENTAL:NO")
add_compile_options($<IF:$<CONFIG:Debug>,/MTd,/MT>)

set(OBSInstallerUtils_HEADERS
	nsis/api.h
	nsis/nsis_tchar.h
	nsis/pluginapi.h
	)

set(OBSInstallerUtils_SOURCES
	nsis/pluginapi.c
	OBSUtil.c
	)

add_library(OBSInstallerUtils SHARED
	${OBSInstallerUtils_HEADERS}
	${OBSInstallerUtils_SOURCES}
	)
target_link_libraries(OBSInstallerUtils
	${OBSInstallerUtils_LIBRARIES}
	rstrtmgr
	)
