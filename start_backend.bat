@echo off
echo ============================================================
echo  IRONCLAD — Backend Server
echo ============================================================
cd /d E:\2030_PROJECTS\IRONCLAD_2
"C:\Users\jaswa\anaconda3\python.exe" -m uvicorn ironclad.server.app:app --host 0.0.0.0 --port 8000 --reload
pause
