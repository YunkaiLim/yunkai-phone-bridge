"""Narrow MCP raw-input boundary; all existing tools keep SDK behavior."""
import json

from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult, TextContent

import companion_owned
from reflex_tap import ReflexTapExecutor, TOOL_NAME, request_schema, response_schema
from reflex_status import STATUS_TOOL_NAME, attach_runtime_epoch, read_status, status_schema


executor = ReflexTapExecutor()  # Default deny; native wrapper stays lazy until permission passes.
attach_runtime_epoch(executor)  # Passive host metadata; tap wire and behavior remain unchanged.
companion_executor = companion_owned.CompanionOwnedExecutor()  # Default off; no I/O on import.


class ReflexMCPServer(MCPServer):
    async def list_tools(self):
        tools = await super().list_tools()
        for tool in tools:
            if tool.name == companion_owned.STATUS_TOOL_NAME:
                tool.input_schema = {"type": "object", "additionalProperties": False,
                                     "properties": {}, "required": []}
                tool.output_schema = companion_owned.status_schema()
            if tool.name == companion_owned.TOOL_NAME:
                tool.input_schema = {"type": "object", "additionalProperties": False,
                                     "required": ["request"],
                                     "properties": {"request": companion_owned.request_schema()}}
                tool.output_schema = companion_owned.response_schema()
            if tool.name == STATUS_TOOL_NAME:
                tool.input_schema = {"type": "object", "additionalProperties": False,
                                     "properties": {}, "required": []}
                tool.output_schema = status_schema()
            if tool.name == TOOL_NAME:
                tool.input_schema = {"type": "object", "additionalProperties": False,
                                     "required": ["request"], "properties": {"request": request_schema()}}
                tool.output_schema = response_schema()
        return tools

    async def call_tool(self, name, arguments, context=None):
        if name == companion_owned.STATUS_TOOL_NAME:
            if arguments is not None and (type(arguments) is not dict or arguments):
                return CallToolResult(content=[TextContent(type="text", text="INVALID_STATUS_REQUEST")], is_error=True)
            result = companion_owned.status()
            return CallToolResult(content=[TextContent(type="text", text=json.dumps(result))],
                                  structured_content=result, is_error=False)
        if name == companion_owned.TOOL_NAME:
            request = (arguments["request"] if type(arguments) is dict and len(arguments) == 1
                       and all(type(key) is str for key in arguments) and "request" in arguments else None)
            result = await companion_executor.execute(request)
            return CallToolResult(content=[TextContent(type="text", text=json.dumps(result))],
                                  structured_content=result, is_error=False)
        if name == STATUS_TOOL_NAME:
            if arguments is not None and (type(arguments) is not dict or arguments):
                return CallToolResult(content=[TextContent(type="text", text="INVALID_STATUS_REQUEST")], is_error=True)
            try:
                result = read_status(executor.runtime_epoch)
            except Exception:
                return CallToolResult(content=[TextContent(type="text", text="STATUS_UNAVAILABLE")], is_error=True)
            return CallToolResult(content=[TextContent(type="text", text=json.dumps(result))],
                                  structured_content=result, is_error=False)
        if name == TOOL_NAME:
            request = (arguments["request"] if type(arguments) is dict and len(arguments) == 1
                       and all(type(key) is str for key in arguments) and "request" in arguments else None)
            result = executor.tap(request)
            return CallToolResult(content=[TextContent(type="text", text=json.dumps(result))],
                                  structured_content=result, is_error=False)
        return await super().call_tool(name, arguments, context)
