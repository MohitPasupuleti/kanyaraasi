@echo off
echo ========================================
echo   LeakLockAI - Starting Application
echo ========================================
echo.

REM Start backend in a new window
echo Starting backend server...
start "LeakLockAI Backend" cmd /k "cd src && python main.py"

REM Wait a bit for backend to start
timeout /t 3 /nobreak > nul

REM Start frontend in a new window
echo Starting frontend...
start "LeakLockAI Frontend" cmd /k "cd frontend && npm run dev"

echo.
echo ========================================
echo   Both servers are starting!
echo ========================================
echo   Backend:  http://localhost:8000
echo   Frontend: http://localhost:3000
echo   Docs:     http://localhost:8000/docs
echo ========================================
echo.
pause
