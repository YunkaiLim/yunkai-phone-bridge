from server import server


if __name__ == "__main__":
    # Secure MCP Tunnel can launch this file as a local stdio MCP process.
    # Nothing is bound to a public or LAN-facing TCP port.
    server.run(transport="stdio")
