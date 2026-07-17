import hashlib
from typing import Any, Dict, Optional
from fastapi import APIRouter, Request, Response

router = APIRouter()

# Constants provided in the spec
NORMALIZED_EMAIL = "22f3002249@ds.study.iitm.ac.in"

@router.post("/mcp")
async def mcp_endpoint(request: Request):
    """
    MCP Server endpoint handling JSON-RPC 2.0 requests over HTTPS.
    """
    payload = await request.json()
    method = payload.get("method")
    request_id = payload.get("id")

    # 1. Handle Initialization
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "exam-mcp-server",
                    "version": "1.0.0"
                }
            }
        }

    # 2. Handle Initialized Notification
    elif method == "notifications/initialized":
        # Notifications do not return a response in JSON-RPC
        return Response(status_code=204)

    # 3. List Tools
    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "tools": [
                    {
                        "name": "solve_challenge",
                        "description": "Solves the hex challenge provided in HTTP headers.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {},
                            "required": []
                        }
                    }
                ]
            }
        }

    # 4. Call Tool
    elif method == "tools/call":
        params = payload.get("params", {})
        tool_name = params.get("name")

        if tool_name == "solve_challenge":
            # READ FROM HEADERS as per spec
            challenge = request.headers.get("X-Exam-Challenge", "")
            
            # Logic: SHA-256("${challenge}:${normalizedEmail}") -> first 16 hex chars
            input_str = f"{challenge}:{NORMALIZED_EMAIL}"
            hash_object = hashlib.sha256(input_str.encode("utf-8"))
            hex_dig = hash_object.hexdigest()
            result_text = hex_dig[:16]

            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": result_text
                        }
                    ],
                    "isError": False
                }
            }

    # Default Error for unknown methods
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": -32601,
            "message": "Method not found"
        }
    }
