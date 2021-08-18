@ECHO OFF

SET COMPOSE_FILE_PATH=%CD%\docker\docker-compose.yml

IF [%1]==[] (
    echo "Usage: %0 {start|stop|purge|tail}"
    GOTO END
)

IF %1==start (
    CALL :start
    CALL :tail
    GOTO END
)
IF %1==stop (
    CALL :down
    GOTO END
)
IF %1==purge (
    CALL:down
    CALL:purge
    GOTO END
)
IF %1==tail (
    CALL :tail
    GOTO END
)
echo "Usage: %0 {start|stop|purge|tail}"
:END
EXIT /B %ERRORLEVEL%

:start
    docker volume create openssh-keys-volume
    docker-compose -f "%COMPOSE_FILE_PATH%" up --build -d
EXIT /B 0
:down
    if exist "%COMPOSE_FILE_PATH%" (
        docker-compose -f "%COMPOSE_FILE_PATH%" down
    )
EXIT /B 0
:tail
    docker-compose -f "%COMPOSE_FILE_PATH%" logs -f
EXIT /B 0
:tail_all
    docker-compose -f "%COMPOSE_FILE_PATH%" logs --tail="all"
EXIT /B 0
:purge
    docker volume rm -f openssh-keys-volume
EXIT /B 0