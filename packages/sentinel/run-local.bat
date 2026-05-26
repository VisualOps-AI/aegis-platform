@echo off
REM Local development launcher - runs all services (Windows)

echo.
echo ========================================
echo   Witness Platform - Local Dev
echo ========================================
echo.

echo Starting Witness Governance on :9000...
start "Witness Governance" cmd /c "cd services\governance && python -m uvicorn server:app --host 0.0.0.0 --port 9000"

timeout /t 2 /nobreak >nul

if defined OPENAI_API_KEY (
    timeout /t 1 /nobreak >nul
    echo Starting Witness Sentinel on :8080...
    start "Witness Sentinel" cmd /c "cd services\sentinel && python -m uvicorn main:app --host 0.0.0.0 --port 8080"
) else (
    echo.
    echo WARNING: OPENAI_API_KEY not set - Witness Sentinel not started
)

echo.
echo ========================================
echo   Services running:
echo     Witness Governance: http://localhost:9000
if defined OPENAI_API_KEY echo     Witness Sentinel:   http://localhost:8080
echo.
echo   Close the spawned windows to stop
echo ========================================
echo.

pause
