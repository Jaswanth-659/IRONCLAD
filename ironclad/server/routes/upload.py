"""
Upload & Synthetic Capture Ingestion Routes.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
import uuid
import aiofiles
from fastapi import APIRouter, BackgroundTasks, File, HTTPException, UploadFile

from ironclad.core.logging import get_logger
from ironclad.server.database import create_session
from ironclad.server.models import UploadResponse
from ironclad.server.pipeline_runner import execute_pcap_analysis
from scripts.generate_synthetic_pcap import generate_test_pcap

router = APIRouter(prefix="/api/upload", tags=["Upload"])
logger = get_logger("server.routes.upload")

UPLOAD_DIR = Path("data/uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


@router.post("/pcap", response_model=UploadResponse)
async def upload_pcap(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
) -> UploadResponse:
    """
    Accepts PCAP or PCAPNG upload, validates file integrity, and triggers background analysis.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename in upload.")

    ext = Path(file.filename).suffix.lower()
    if ext not in (".pcap", ".pcapng", ".cap"):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format '{ext}'. Must be .pcap or .pcapng."
        )

    task_id = str(uuid.uuid4())
    save_path = UPLOAD_DIR / f"{task_id}_{file.filename}"

    file_size = 0
    try:
        async with aiofiles.open(save_path, "wb") as out_file:
            while content := await file.read(1024 * 64):  # 64KB chunks
                file_size += len(content)
                await out_file.write(content)
    except Exception as e:
        logger.error("Failed to save uploaded file: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to persist file: {str(e)}") from e

    if file_size == 0:
        if save_path.exists():
            save_path.unlink()
        raise HTTPException(status_code=400, detail="Uploaded capture file is empty (0 bytes).")

    # Initialize session record in SQLite
    create_session(task_id, file.filename, file_size)

    # Launch non-blocking background analysis pipeline
    background_tasks.add_task(execute_pcap_analysis, task_id, str(save_path), file.filename)

    return UploadResponse(
        task_id=task_id,
        filename=file.filename,
        file_size=file_size,
        status="PROCESSING",
        message="PCAP uploaded successfully. Telemetry analysis initiated in background.",
    )


@router.post("/generate-synthetic", response_model=UploadResponse)
async def generate_and_analyze_synthetic(background_tasks: BackgroundTasks) -> UploadResponse:
    """
    1-Click demo endpoint: Generates a realistic synthetic capture (HTTP, SYN scan, exfiltration)
    and executes full analysis.
    """
    task_id = str(uuid.uuid4())
    filename = f"synthetic_trace_{task_id[:8]}.pcap"
    save_path = UPLOAD_DIR / filename

    # Generate synthetic PCAP
    generate_test_pcap(str(save_path))
    file_size = save_path.stat().st_size

    create_session(task_id, filename, file_size)
    background_tasks.add_task(execute_pcap_analysis, task_id, str(save_path), filename)

    return UploadResponse(
        task_id=task_id,
        filename=filename,
        file_size=file_size,
        status="PROCESSING",
        message="Synthetic multi-vector capture generated. Analysis started.",
    )
