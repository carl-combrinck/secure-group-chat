@rem Batch file for executing SecureGroupChat application

@ECHO off

SET LIB_DIR=app\build\libs\app.jar;bouncy_castle\bcpg-jdk15to18-171.jar;bouncy_castle\bcpkix-jdk15to18-171.jar;bouncy_castle\bcprov-ext-jdk15to18-171.jar;bouncy_castle\bcutil-jdk15to18-171.jar

SET argC=0
for %%x in (%*) do SET /A argC+=1

IF "%1" == "ca"  (
  ECHO [SecureGroupChat] Running Certificate Authority...
  java "-cp" "%LIB_DIR%" "com.securegroupchat.CertificateAuthority"
) ELSE (
  IF "%1" == "server" (
    ECHO [SecureGroupChat] Starting server...
    java "-cp" "%LIB_DIR%" "com.securegroupchat.Server" "1234"
  ) ELSE (
    IF "%1" == "client" (
      ECHO [SecureGroupChat] Starting client...
      IF %argC% == 2 (
        java "-cp" "%LIB_DIR%" "com.securegroupchat.Client" "localhost" "1234" "%2"
      ) ELSE (
        java "-cp" "%LIB_DIR%" "com.securegroupchat.Client" "localhost" "1234"
      )
    ) ELSE (
      ECHO [SecureGroupChat] Unrecognised command, terminating.
    )
  )
)