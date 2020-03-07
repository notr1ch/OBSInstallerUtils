project(OBSInstallerUtils)

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
