"""Bound multipart uploads before Starlette spools their full contents."""

from fastapi import HTTPException
from starlette.responses import JSONResponse


class UploadLimitMiddleware:
    def __init__(self, app, max_bytes: int, max_archive_bytes: int = 512 * 1024 * 1024):
        self.app = app
        self.max_bytes = max_bytes
        self.max_archive_bytes = max_archive_bytes

    async def __call__(self, scope, receive, send):
        if (
            scope["type"] != "http"
            or scope["method"] != "POST"
            or not scope["path"].startswith("/api/v1/projects/")
            or not scope["path"].endswith(
                ("/captures", "/action-logs", "/action-logs/preview", "/restore")
            )
        ):
            await self.app(scope, receive, send)
            return
        max_bytes = (
            self.max_archive_bytes
            if scope["path"].endswith("/restore")
            else 17 * 1024 * 1024
            if "/action-logs" in scope["path"]
            else self.max_bytes
        )
        headers = dict(scope.get("headers", []))
        try:
            declared = int(headers.get(b"content-length", b"0"))
        except ValueError:
            await JSONResponse({"detail": "Invalid Content-Length"}, status_code=400)(
                scope, receive, send
            )
            return
        if declared > max_bytes:
            await JSONResponse(
                {"detail": "Upload request exceeds configured limit"}, status_code=413
            )(scope, receive, send)
            return
        consumed = 0

        async def bounded_receive():
            nonlocal consumed
            message = await receive()
            if message["type"] == "http.request":
                consumed += len(message.get("body", b""))
                if consumed > max_bytes:
                    raise HTTPException(413, "Upload request exceeds configured limit")
            return message

        await self.app(scope, bounded_receive, send)
