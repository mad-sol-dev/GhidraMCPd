from mcp.server.fastmcp import FastMCP
import requests

ghidra_server_url = "http://localhost:8080"

mcp = FastMCP("ghidra-mcp")

@mcp.tool()
def list_methods() -> list:
    response = requests.get(f"{ghidra_server_url}/methods")
    return response.text.splitlines() if response.ok else []

@mcp.tool()
def rename_method(method_address: str, new_name: str) -> str:
    payload = {"method_address": method_address, "new_name": new_name}
    response = requests.post(f"{ghidra_server_url}/rename", data=payload)
    return response.text if response.ok else "Failed to rename method"

@mcp.tool()
def list_classes() -> list:
    response = requests.get(f"{ghidra_server_url}/classes")
    return response.text.splitlines() if response.ok else []

@mcp.tool()
def decompile_function(name: str) -> str:
    response = requests.post(f"{ghidra_server_url}/decompile", data=name)
    return response.text if response.ok else "Failed to decompile function"

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    payload = {"oldName": old_name, "newName": new_name}
    response = requests.post(f"{ghidra_server_url}/renameFunction", data=payload)
    return response.text if response.ok else "Failed to rename function"

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    payload = {"address": address, "newName": new_name}
    response = requests.post(f"{ghidra_server_url}/renameData", data=payload)
    return response.text if response.ok else "Failed to rename data"

@mcp.tool()
def list_segments() -> list:
    response = requests.get(f"{ghidra_server_url}/segments")
    return response.text.splitlines() if response.ok else []

@mcp.tool()
def list_imports() -> list:
    response = requests.get(f"{ghidra_server_url}/imports")
    return response.text.splitlines() if response.ok else []

@mcp.tool()
def list_exports() -> list:
    response = requests.get(f"{ghidra_server_url}/exports")
    return response.text.splitlines() if response.ok else []

@mcp.tool()
def list_namespaces() -> list:
    response = requests.get(f"{ghidra_server_url}/namespaces")
    return response.text.splitlines() if response.ok else []

@mcp.tool()
def list_data_items() -> list:
    response = requests.get(f"{ghidra_server_url}/data")
    return response.text.splitlines() if response.ok else []

if __name__ == "__main__":
    mcp.run()

