#!/usr/bin/env python3
"""Universal Catalyst MCP Server - Knowledge Pack Architecture."""

import asyncio
import os
import sys
import logging
import json
import time
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from dotenv import load_dotenv

from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, HTMLResponse

# Import existing components
from .config import MCPConfig
from .audit.audit_system import AuditSystem, ExecutionContext
from .audit.hec_logger import SplunkHECLogger

# Import universal pack system
from .packs import PackRegistry, UniversalToolFactory

# Import OAuth handler
from .oauth import SimpleOAuth

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment
load_dotenv()

# Initialize FastMCP server
mcp = FastMCP("Catalyst MCP Server - Universal")

# Health check endpoint for Docker container monitoring
@mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request) -> JSONResponse:
    """Health check endpoint for Docker container monitoring."""
    return JSONResponse({"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()})

# OAuth endpoints
@mcp.custom_route("/oauth/start", methods=["POST"])
async def start_oauth(request: Request) -> JSONResponse:
    """Start OAuth flow for a specific instance."""
    global oauth_handler

    try:
        data = await request.json()
        instance_url = data.get("instance_url")
        client_id = data.get("client_id")

        if not instance_url or not client_id:
            return JSONResponse({"error": "instance_url and client_id required"}, status_code=400)

        auth_info = await oauth_handler.start_auth_flow(instance_url, client_id)
        return JSONResponse(auth_info)
    except Exception as e:
        logger.error(f"OAuth start error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)

@mcp.custom_route("/callback", methods=["GET"])
async def oauth_callback(request: Request) -> JSONResponse:
    """Handle OAuth callback."""
    global oauth_handler

    try:
        code = request.query_params.get("code")
        state = request.query_params.get("state")
        error = request.query_params.get("error")

        if error:
            return JSONResponse({"error": f"OAuth error: {error}"}, status_code=400)

        if not code or not state:
            return JSONResponse({"error": "Missing code or state"}, status_code=400)

        result = await oauth_handler.handle_callback(code, state)

        if "error" in result:
            return JSONResponse(result, status_code=400)

        # Success - show a simple HTML page
        html = """
        <html>
        <body style="font-family: sans-serif; text-align: center; padding: 50px;">
            <h2>Authentication Successful!</h2>
            <p>You can now close this window and return to your application.</p>
            <script>setTimeout(() => window.close(), 3000);</script>
        </body>
        </html>
        """
        return HTMLResponse(html)

    except Exception as e:
        logger.error(f"OAuth callback error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)

@mcp.custom_route("/oauth/status", methods=["GET"])
async def oauth_status(request: Request) -> JSONResponse:
    """Check OAuth status for an instance."""
    global oauth_handler

    instance_url = request.query_params.get("instance_url")
    if not instance_url:
        return JSONResponse({"error": "instance_url required"}, status_code=400)

    has_token = oauth_handler.get_token(instance_url) is not None
    return JSONResponse({"instance": instance_url, "authenticated": has_token})

# Global pack system components
pack_registry: Optional[PackRegistry] = None
tool_factory: Optional[UniversalToolFactory] = None
config: Optional[MCPConfig] = None
oauth_handler: Optional[SimpleOAuth] = None


def initialize_pack_system() -> bool:
    """Initialize the universal knowledge pack system.
    
    Returns:
        True if initialization succeeded, False otherwise
    """
    global pack_registry, tool_factory
    
    try:
        logger.info("Initializing Universal Knowledge Pack System...")
        
        # Create pack registry
        pack_registry = PackRegistry("knowledge-packs")
        
        # Auto-discover and load all valid packs (excluding .example)
        # No need to specify core packs - will auto-discover from knowledge-packs/
        
        # Create universal tool factory
        tool_factory = UniversalToolFactory(mcp)
        
        # Load and register core packs
        core_packs = pack_registry.initialize_core_packs()
        
        total_tools = 0
        for pack_name, pack in core_packs.items():
            registered_tools = tool_factory.register_pack_tools(pack_name, pack)
            total_tools += len(registered_tools)
            logger.info(f"Pack '{pack_name}': {len(registered_tools)} tools registered")
        
        # Log pack system statistics
        stats = pack_registry.get_pack_statistics()
        logger.info(f"Pack System Initialized: {stats['total_packs']} packs, {total_tools} tools")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize pack system: {e}")
        return False


@mcp.tool
async def trigger_oauth_authentication(instance_url: str, client_id: str) -> Dict[str, Any]:
    """Trigger OAuth authentication for a specific instance.

    Args:
        instance_url: The URL of the instance to authenticate with (e.g., https://mycompany.splunkcloud.com)
        client_id: OAuth client ID for your application

    Returns:
        Authentication URL and instructions
    """
    global oauth_handler

    if not oauth_handler:
        return {"error": "OAuth handler not initialized"}

    try:
        auth_info = await oauth_handler.start_auth_flow(instance_url, client_id)
        return {
            "auth_url": auth_info["auth_url"],
            "instructions": "Please visit the auth_url in your browser to authenticate",
            "state": auth_info["state"],
            "callback_url": "http://localhost:8443/callback"
        }
    except Exception as e:
        return {"error": f"Failed to start OAuth flow: {str(e)}"}

@mcp.tool
async def check_oauth_status(instance_url: str) -> Dict[str, Any]:
    """Check OAuth authentication status for an instance.

    Args:
        instance_url: The URL of the instance to check

    Returns:
        Authentication status
    """
    global oauth_handler

    if not oauth_handler:
        return {"error": "OAuth handler not initialized"}

    has_token = oauth_handler.get_token(instance_url) is not None
    return {
        "instance": instance_url,
        "authenticated": has_token,
        "message": "Authenticated" if has_token else "Not authenticated - use trigger_oauth_authentication"
    }

@mcp.tool
async def list_knowledge_packs() -> Dict[str, Any]:
    """List all available knowledge packs and their status."""
    if not pack_registry:
        return {"error": "Pack system not initialized"}
    
    try:
        available_packs = pack_registry.list_available_packs()
        loaded_packs = pack_registry.list_loaded_packs()
        
        pack_info = []
        for pack_name in available_packs:
            info = pack_registry.get_pack_info(pack_name)
            if info:
                info["loaded"] = pack_name in loaded_packs
                pack_info.append(info)
        
        stats = pack_registry.get_pack_statistics()
        
        return {
            "available_packs": len(available_packs),
            "loaded_packs": len(loaded_packs),
            "total_tools": stats["total_tools"],
            "packs": pack_info,
            "statistics": stats
        }
        
    except Exception as e:
        logger.error(f"Failed to list knowledge packs: {e}")
        return {"error": str(e)}


@mcp.tool  
async def reload_knowledge_pack(pack_name: str) -> Dict[str, Any]:
    """Reload a specific knowledge pack from disk.
    
    Args:
        pack_name: Name of pack to reload
    """
    if not pack_registry or not tool_factory:
        return {"error": "Pack system not initialized"}
    
    try:
        logger.info(f"Reloading knowledge pack: {pack_name}")
        
        # Unregister existing tools
        unregistered = tool_factory.unregister_pack_tools(pack_name)
        logger.info(f"Unregistered {len(unregistered)} tools from {pack_name}")
        
        # Reload pack
        pack = pack_registry.reload_pack(pack_name)
        if not pack:
            return {"error": f"Failed to reload pack '{pack_name}'"}
        
        # Re-register tools
        registered = tool_factory.register_pack_tools(pack_name, pack)
        logger.info(f"Registered {len(registered)} tools for {pack_name}")
        
        return {
            "success": True,
            "pack_name": pack_name,
            "pack_version": pack.metadata.version,
            "tools_registered": len(registered),
            "tools": registered
        }
        
    except Exception as e:
        logger.error(f"Failed to reload pack {pack_name}: {e}")
        return {"error": str(e)}


@mcp.tool
async def get_pack_status() -> Dict[str, Any]:
    """Get detailed status of the knowledge pack system."""
    if not pack_registry or not tool_factory:
        return {"error": "Pack system not initialized"}
    
    try:
        stats = pack_registry.get_pack_statistics()
        tool_counts = tool_factory.get_tool_count_by_pack()
        
        loaded_packs = []
        for pack_name in pack_registry.list_loaded_packs():
            pack = pack_registry.get_pack(pack_name, lazy_load=False)
            if pack:
                loaded_packs.append({
                    "name": pack.metadata.name,
                    "pack_id": pack_name,
                    "version": pack.metadata.version,
                    "vendor": pack.metadata.vendor,
                    "domain": pack.metadata.domain,
                    "tools_count": tool_counts.get(pack_name, 0),
                    "pricing_tier": pack.metadata.pricing_tier
                })
        
        return {
            "system_status": "operational",
            "statistics": stats,
            "loaded_packs": loaded_packs,
            "tool_distribution": tool_counts
        }
        
    except Exception as e:
        logger.error(f"Failed to get pack status: {e}")
        return {"error": str(e)}


# Legacy Splunk tools for compatibility during migration
@mcp.tool
async def current_user() -> Dict[str, Any]:
    """Get current Splunk user information - Legacy compatibility tool."""
    # This is a legacy tool that will eventually be replaced by the pack system
    # For now, we'll implement a simple version
    
    try:
        config = MCPConfig.from_env()
        return {
            "username": config.splunk_user,
            "splunk_url": config.splunk_url,
            "note": "This is a legacy compatibility tool. Use knowledge packs for new implementations."
        }
    except Exception as e:
        return {"error": str(e)}


async def startup_sequence():
    """Run server startup sequence."""
    global config, oauth_handler

    logger.info("Starting Catalyst MCP Server - Universal Knowledge Pack Edition")

    # Load configuration
    try:
        config = MCPConfig.from_env()
        config.validate()
        logger.info("Configuration loaded successfully")
    except Exception as e:
        logger.error(f"Configuration error: {e}")
        return False

    # Initialize OAuth handler
    oauth_handler = SimpleOAuth()
    logger.info("OAuth handler initialized")
    
    # Initialize pack system
    if not initialize_pack_system():
        logger.error("Pack system initialization failed - server cannot start")
        return False
    
    # Initialize audit system if HEC is enabled
    if config.enable_hec_logging and config.splunk_hec_token:
        try:
            hec_logger = SplunkHECLogger(
                hec_url=config.splunk_hec_url,
                hec_token=config.splunk_hec_token,
                index=config.splunk_hec_index,
                source="catalyst_universal"
            )
            await hec_logger.start()
            logger.info("HEC audit logging enabled")
        except Exception as e:
            logger.warning(f"HEC audit logging failed to initialize: {e}")
    
    logger.info("Catalyst MCP Server startup complete")
    return True


async def startup_and_run():
    """Run startup sequence and start server."""
    # Run startup sequence
    if not await startup_sequence():
        sys.exit(1)
    
    # Return control - mcp.run will handle the server
    return True

def sync_main():
    """Synchronous entry point for the server."""
    try:
        # Run async startup
        startup_result = asyncio.run(startup_and_run())
        if not startup_result:
            sys.exit(1)
        
        # Start the FastMCP server (handles its own event loop)
        port = config.port if config else 8443
        logger.info(f"Starting server on port {port}")
        mcp.run(transport="http", port=port, host="0.0.0.0")
        
    except KeyboardInterrupt:
        logger.info("Server shutting down...")
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    sync_main()