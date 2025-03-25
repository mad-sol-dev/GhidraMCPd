# GhidraMCP

## Features
MCP Server + Ghidra Plugin

- Automatically rename methods and data
- List methods, classes, imports, and exports
- Decompile and analyze

## Installing

### Prerequisites
- Mac / Windows
- Install [Ghidra](https://ghidra-sre.org)
- Python3

### Ghidra
First, download the latest release from this repository. This contains the Ghidra plugin and Python MCP client. Then, you can directly import the plugin into Ghidra.

1. Run Ghidra
2. Select `File` -> `Install Extensions`
3. Click the `+` button
4. Select the `GhidraMCP-1-0.zip` (or your chosen version) from the downloaded release
5. Restart Ghidra
6. Make sure the GhidraMCPPlugin is enabled in `File` -> `Configure` -> `Developer`


### Option 1: Claude Desktop
Go to Claude > Settings > Developer > Edit Config > claude_desktop_config.json and add the following:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": [
        "/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py"
      ]
    }
  }
}
```

Alternatively, edit this file `/Users/YOUR_USER/Library/Application Support/Claude/claude_desktop_config.json`.

### Option 2: 5ire
Another MCP client that supports multiple models on the backend is [5ire](https://github.com/nanbingxyz/5ire). To set up GhidraMCP, open 5ire and go to `Tools` -> `New` and set the following configurations:

1. Tool Key: ghidra
2. Name: GhidraMCP
3. Command: `python /ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py`

## Building from Source
Build with Maven by running:

`mvn clean package assembly:single`

The generated zip file includes the built Ghidra plugin and its resources.

- lib/GhidraMCP.jar
- extensions.properties
- Module.manifest
