import asyncio
import json
import os
from typing import Any, Dict

import aiocoap.resource as resource
import aiocoap
import httpx

FASTAPI_BASE_URL = os.getenv("FASTAPI_BASE_URL", "http://nac_api:8000")
COAP_BIND_HOST = os.getenv("COAP_BIND_HOST", "0.0.0.0")
COAP_BIND_PORT = int(os.getenv("COAP_BIND_PORT", "5683"))
DEFAULT_MESSAGE_TYPE = os.getenv("DEFAULT_MESSAGE_TYPE", "coap")


class TelemetryResource(resource.Resource):
    async def render_post(self, request: aiocoap.Message) -> aiocoap.Message:
        payload_text = request.payload.decode("utf-8", errors="ignore").strip()
        client_addr = ""
        if getattr(request.remote, "hostinfo", None):
            client_addr = request.remote.hostinfo

        telemetry = self._extract_telemetry(payload_text)
        telemetry["source_ip"] = telemetry.get("source_ip") or client_addr

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(
                    f"{FASTAPI_BASE_URL}/iot/telemetry",
                    json=telemetry,
                )

            if response.status_code >= 400:
                detail = response.text[:200]
                body = f"rejected:{response.status_code}:{detail}".encode("utf-8")
                return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=body)

            return aiocoap.Message(code=aiocoap.CHANGED, payload=b"accepted")
        except Exception as exc:
            message = f"bridge_error:{str(exc)[:160]}".encode("utf-8")
            return aiocoap.Message(code=aiocoap.SERVICE_UNAVAILABLE, payload=message)

    def _extract_telemetry(self, payload_text: str) -> Dict[str, Any]:
        default_payload = {
            "device_mac": "00:11:22:33:44:55",
            "payload": payload_text or "",
            "message_type": DEFAULT_MESSAGE_TYPE,
            "path": "/telemetry",
            "source_ip": "",
        }

        if not payload_text:
            return default_payload

        try:
            parsed = json.loads(payload_text)
            return {
                "device_mac": parsed.get("device_mac", default_payload["device_mac"]),
                "payload": str(parsed.get("payload", "")),
                "message_type": parsed.get("message_type", DEFAULT_MESSAGE_TYPE),
                "path": parsed.get("path", "/telemetry"),
                "source_ip": parsed.get("source_ip", ""),
            }
        except json.JSONDecodeError:
            return default_payload


async def main() -> None:
    root = resource.Site()
    root.add_resource(("telemetry",), TelemetryResource())

    await aiocoap.Context.create_server_context(
        root,
        bind=(COAP_BIND_HOST, COAP_BIND_PORT),
    )

    print(f"COAP bridge running on coap://{COAP_BIND_HOST}:{COAP_BIND_PORT}/telemetry")
    print(f"Forwarding telemetry to {FASTAPI_BASE_URL}/iot/telemetry")

    await asyncio.get_running_loop().create_future()


if __name__ == "__main__":
    asyncio.run(main())
