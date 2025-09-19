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
from contextvars import ContextVar
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

# Import OAuth and SAML handlers
from .oauth import SimpleOAuth
from .saml_auth import SplunkSAMLAuth

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment
load_dotenv()

# Initialize FastMCP server
mcp = FastMCP("Catalyst MCP Server - Universal")

# User context for passthrough authentication
user_context: ContextVar[Dict[str, Any]] = ContextVar('user_context', default={})


async def auth_middleware(request: Request, call_next):
    """Extract user authentication context from request headers."""
    try:
        context = {}
        
        # Extract Authorization header
        auth_header = request.headers.get('authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]  # Remove 'Bearer ' prefix
            context.update({
                'token': token,
                'headers': {'Authorization': auth_header}
            })
        
        # Extract API key header
        api_key = request.headers.get('x-api-key', '')
        if api_key:
            context['api_key'] = api_key
        
        # Extract Git authentication headers
        git_token = request.headers.get('x-git-token', '')
        if git_token:
            context['git_token'] = git_token
            
        git_username = request.headers.get('x-git-username', '')
        if git_username:
            context['git_username'] = git_username
            
        git_password = request.headers.get('x-git-password', '')
        if git_password:
            context['git_password'] = git_password
        
        # Set the complete context
        user_context.set(context)
        
        # Call next middleware/handler
        response = await call_next(request)
        return response
        
    except Exception as e:
        logger.error(f"Auth middleware error: {e}")
        # Clear context on error
        user_context.set({})
        response = await call_next(request)
        return response


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

# SAML endpoints
@mcp.custom_route("/saml/start", methods=["GET"])
async def start_saml_auth(request: Request) -> HTMLResponse:
    """Start SAML authentication flow."""
    global saml_handler

    state = request.query_params.get("state")
    splunk_url = request.query_params.get("splunk_url")

    if not state or not splunk_url:
        return HTMLResponse("<h2>Error: Missing parameters</h2>", status_code=400)

    # Create HTML page that will handle SAML authentication
    html = f"""
    <html>
    <head>
        <title>Splunk SAML Authentication</title>
        <style>
            body {{ font-family: sans-serif; text-align: center; padding: 50px; }}
            .auth-container {{ max-width: 600px; margin: 0 auto; }}
            .btn {{ padding: 12px 24px; background: #007acc; color: white; text-decoration: none; border-radius: 4px; }}
            .status {{ margin: 20px 0; }}
        </style>
    </head>
    <body>
        <div class="auth-container">
            <h2>🔐 Splunk Authentication</h2>
            <p>Click the button below to authenticate with your Splunk instance:</p>

            <div class="status" id="status">
                <a href="{splunk_url}/en-US/account/login" class="btn" onclick="startAuth()">
                    Authenticate to Splunk
                </a>
            </div>

            <div id="instructions" style="display: none;">
                <p>After logging in to Splunk, return to this page to complete authentication.</p>
                <button onclick="completeAuth()" class="btn">I've logged in - Complete Authentication</button>
            </div>
        </div>

        <script>
        function startAuth() {{
            document.getElementById('instructions').style.display = 'block';
            document.getElementById('status').innerHTML = '<p>Please log in to Splunk in the new tab/window...</p>';
        }}

        async function completeAuth() {{
            try {{
                document.getElementById('status').innerHTML = '<p>Creating authentication token...</p>';

                // Try to create a token using the user's Splunk session
                const response = await fetch('{splunk_url}/services/auth/tokens', {{
                    method: 'POST',
                    credentials: 'include',
                    headers: {{
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'X-Requested-With': 'XMLHttpRequest'
                    }},
                    body: 'name=mcp-saml-token&audience=users&expires_on=%2B30d'
                }});

                if (response.ok) {{
                    const text = await response.text();

                    // Extract token from XML response
                    const parser = new DOMParser();
                    const xmlDoc = parser.parseFromString(text, "text/xml");
                    const tokenElement = xmlDoc.getElementsByTagName("content")[0];

                    if (tokenElement) {{
                        const token = tokenElement.textContent;

                        // Send token to our server
                        const storeResponse = await fetch('/saml/token', {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/json' }},
                            body: JSON.stringify({{
                                state: '{state}',
                                token: token,
                                splunk_url: '{splunk_url}'
                            }})
                        }});

                        if (storeResponse.ok) {{
                            document.getElementById('status').innerHTML = '<h3>✅ Authentication Successful!</h3><p>You can close this window.</p>';
                            setTimeout(() => window.close(), 3000);
                        }} else {{
                            throw new Error('Failed to store token');
                        }}
                    }} else {{
                        throw new Error('No token in response');
                    }}
                }} else {{
                    throw new Error('Failed to create token');
                }}
            }} catch (error) {{
                document.getElementById('status').innerHTML = '<h3>❌ Authentication Failed</h3><p>' + error.message + '</p><p>Please ensure you are logged in to Splunk and try again.</p>';
            }}
        }}
        </script>
    </body>
    </html>
    """

    return HTMLResponse(html)

@mcp.custom_route("/saml/token", methods=["POST"])
async def receive_saml_token(request: Request) -> JSONResponse:
    """Receive SAML authentication token from browser."""
    global saml_handler

    try:
        data = await request.json()
        state = data.get("state")
        token = data.get("token")
        splunk_url = data.get("splunk_url")

        if not all([state, token, splunk_url]):
            return JSONResponse({"error": "Missing required fields"}, status_code=400)

        # Verify state
        auth_info = saml_handler.get_pending_auth(state)
        if not auth_info:
            return JSONResponse({"error": "Invalid or expired state"}, status_code=400)

        # Store token
        saml_handler.store_token(splunk_url, token)

        return JSONResponse({"status": "success", "instance": splunk_url})

    except Exception as e:
        logger.error(f"SAML token storage error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)

@mcp.custom_route("/saml/status", methods=["GET"])
async def saml_auth_status(request: Request) -> JSONResponse:
    """Check SAML authentication status."""
    global saml_handler

    instance_url = request.query_params.get("instance_url")
    if not instance_url:
        return JSONResponse({"error": "instance_url required"}, status_code=400)

    status = saml_handler.get_auth_status(instance_url)
    return JSONResponse(status)

# Global pack system components
pack_registry: Optional[PackRegistry] = None
tool_factory: Optional[UniversalToolFactory] = None
config: Optional[MCPConfig] = None
oauth_handler: Optional[SimpleOAuth] = None
saml_handler: Optional[SplunkSAMLAuth] = None


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
async def trigger_saml_authentication(instance_url: str) -> Dict[str, Any]:
    """Trigger SAML authentication for a Splunk instance.

    Args:
        instance_url: The URL of the Splunk instance (e.g., https://company.splunkcloud.com)

    Returns:
        Authentication URL and instructions
    """
    global saml_handler

    if not saml_handler:
        return {"error": "SAML handler not initialized"}

    try:
        # Auto-detect auth method first
        auth_method = await saml_handler.detect_auth_method(instance_url)

        if auth_method == "basic":
            return {
                "error": "Instance does not appear to use SAML authentication",
                "suggestion": "Try basic authentication or trigger_oauth_authentication instead"
            }

        auth_info = await saml_handler.start_saml_flow(instance_url)
        return {
            "auth_url": auth_info["auth_url"],
            "instructions": "Please visit the auth_url in your browser to authenticate via SAML/SSO",
            "state": auth_info["state"],
            "method": "saml"
        }
    except Exception as e:
        return {"error": f"Failed to start SAML authentication: {str(e)}"}

@mcp.tool
async def check_saml_status(instance_url: str) -> Dict[str, Any]:
    """Check SAML authentication status for a Splunk instance.

    Args:
        instance_url: The URL of the Splunk instance to check

    Returns:
        Authentication status
    """
    global saml_handler

    if not saml_handler:
        return {"error": "SAML handler not initialized"}

    return saml_handler.get_auth_status(instance_url)

@mcp.tool
async def detect_splunk_auth_method(instance_url: str) -> Dict[str, Any]:
    """Auto-detect the authentication method for a Splunk instance.

    Args:
        instance_url: The URL of the Splunk instance

    Returns:
        Detected authentication method and recommendations
    """
    global saml_handler

    if not saml_handler:
        return {"error": "SAML handler not initialized"}

    try:
        auth_method = await saml_handler.detect_auth_method(instance_url)

        recommendations = {
            "saml": "Use trigger_saml_authentication for SAML/SSO authentication",
            "basic": "Use basic authentication or trigger_oauth_authentication if OAuth is configured"
        }

        return {
            "instance": instance_url,
            "detected_method": auth_method,
            "recommendation": recommendations.get(auth_method, "Unknown authentication method")
        }
    except Exception as e:
        return {"error": f"Failed to detect authentication method: {str(e)}"}

@mcp.tool
async def list_authenticated_instances() -> Dict[str, Any]:
    """List all instances with active authentication.

    Returns:
        Dictionary of authenticated instances and their status
    """
    global oauth_handler, saml_handler

    result = {"oauth_instances": {}, "saml_instances": {}}

    if oauth_handler:
        # Get OAuth authenticated instances (simplified)
        for url, token_data in oauth_handler.tokens.items():
            result["oauth_instances"][url] = {
                "authenticated": True,
                "method": "oauth"
            }

    if saml_handler:
        result["saml_instances"] = saml_handler.list_authenticated_instances()

    return result

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


# Git pack loader internal API endpoints
@mcp.custom_route("/internal/git-pack-loader/load", methods=["POST"])
async def load_git_pack_endpoint(request: Request) -> JSONResponse:
    """Load a pack from Git repository using user credentials."""
    if not pack_registry:
        return JSONResponse({"error": "Pack system not initialized"}, status_code=500)
    
    try:
        # Parse request body
        body = await request.json()
        repo_url = body.get("repo_url")
        pack_path = body.get("pack_path")
        env_vars = body.get("env_vars")
        branch = body.get("branch", "main")
        pack_name = body.get("pack_name")
        
        if not repo_url:
            return JSONResponse({"error": "repo_url is required"}, status_code=400)
        
        # Get user context from middleware
        context = user_context.get()
        
        # Load Git pack
        result = pack_registry.load_git_pack(
            repo_url=repo_url,
            user_context=context,
            pack_path=pack_path,
            env_vars=env_vars,
            branch=branch,
            pack_name=pack_name
        )
        
        if result.get("error"):
            return JSONResponse(result, status_code=400)
        
        # If successful, register pack tools
        if tool_factory and result.get("success"):
            loaded_pack_name = result.get("pack_name")
            pack = pack_registry.get_pack(loaded_pack_name, lazy_load=False)
            if pack:
                registered_tools = tool_factory.register_pack_tools(loaded_pack_name, pack)
                result["tools_registered"] = len(registered_tools)
                logger.info(f"Git pack '{loaded_pack_name}': {len(registered_tools)} tools registered")
        
        return JSONResponse(result)
        
    except Exception as e:
        logger.error(f"Git pack load endpoint error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@mcp.custom_route("/internal/git-pack-loader/update", methods=["POST"])
async def update_git_pack_endpoint(request: Request) -> JSONResponse:
    """Update an existing Git pack."""
    if not pack_registry:
        return JSONResponse({"error": "Pack system not initialized"}, status_code=500)
    
    try:
        body = await request.json()
        pack_name = body.get("pack_name")
        branch = body.get("branch")
        
        if not pack_name:
            return JSONResponse({"error": "pack_name is required"}, status_code=400)
        
        # Get user context from middleware
        context = user_context.get()
        
        # Update Git pack
        result = pack_registry.update_git_pack(pack_name, context, branch)
        
        if result.get("error"):
            return JSONResponse(result, status_code=400)
        
        # Re-register tools if successful
        if tool_factory and result.get("success"):
            # Unregister old tools
            unregistered = tool_factory.unregister_pack_tools(pack_name)
            logger.info(f"Unregistered {len(unregistered)} tools from {pack_name}")
            
            # Register updated tools
            pack = pack_registry.get_pack(pack_name, lazy_load=False)
            if pack:
                registered = tool_factory.register_pack_tools(pack_name, pack)
                result["tools_registered"] = len(registered)
                logger.info(f"Re-registered {len(registered)} tools for {pack_name}")
        
        return JSONResponse(result)
        
    except Exception as e:
        logger.error(f"Git pack update endpoint error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@mcp.custom_route("/internal/git-pack-loader/list", methods=["GET"])
async def list_git_packs_endpoint(request: Request) -> JSONResponse:
    """List all loaded Git packs."""
    if not pack_registry:
        return JSONResponse({"error": "Pack system not initialized"}, status_code=500)
    
    try:
        result = pack_registry.list_git_packs()
        
        # Enhance with tool counts
        if "packs" in result:
            for pack_info in result["packs"]:
                pack_name = pack_info.get("name")
                if pack_name and tool_factory:
                    tool_counts = tool_factory.get_tool_count_by_pack()
                    pack_info["tools_registered"] = tool_counts.get(pack_name, 0)
                    
                # Add environment variable count
                env_vars = pack_info.get("env_vars", {})
                pack_info["env_vars_count"] = len(env_vars) if env_vars else 0
        
        return JSONResponse(result)
        
    except Exception as e:
        logger.error(f"Git pack list endpoint error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@mcp.custom_route("/internal/git-pack-loader/remove", methods=["DELETE"])
async def remove_git_pack_endpoint(request: Request) -> JSONResponse:
    """Remove a Git pack from runtime."""
    if not pack_registry:
        return JSONResponse({"error": "Pack system not initialized"}, status_code=500)
    
    try:
        body = await request.json()
        pack_name = body.get("pack_name")
        
        if not pack_name:
            return JSONResponse({"error": "pack_name is required"}, status_code=400)
        
        # Unregister tools first
        if tool_factory:
            unregistered = tool_factory.unregister_pack_tools(pack_name)
            logger.info(f"Unregistered {len(unregistered)} tools from {pack_name}")
        
        # Remove Git pack
        result = pack_registry.remove_git_pack(pack_name)
        
        if result.get("success") and tool_factory:
            result["tools_unregistered"] = len(unregistered) if 'unregistered' in locals() else 0
        
        return JSONResponse(result)
        
    except Exception as e:
        logger.error(f"Git pack remove endpoint error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@mcp.custom_route("/internal/git-pack-loader/info/{pack_name}", methods=["GET"])
async def get_git_pack_info_endpoint(request: Request) -> JSONResponse:
    """Get detailed information about a Git pack."""
    if not pack_registry:
        return JSONResponse({"error": "Pack system not initialized"}, status_code=500)
    
    try:
        pack_name = request.path_params.get("pack_name")
        
        if not pack_name:
            return JSONResponse({"error": "pack_name is required"}, status_code=400)
        
        result = pack_registry.get_git_pack_info(pack_name)
        
        if result.get("error"):
            return JSONResponse(result, status_code=404)
        
        # Enhance with pack details
        pack = pack_registry.get_pack(pack_name, lazy_load=False)
        if pack:
            result["tools"] = [{"name": tool_name} for tool_name in pack.tools.keys()]
            result["prompts"] = [{"name": prompt_name} for prompt_name in pack.prompts.keys()]
        
        # Add tool registration count
        if tool_factory:
            tool_counts = tool_factory.get_tool_count_by_pack()
            result["tools_registered"] = tool_counts.get(pack_name, 0)
        
        return JSONResponse(result)
        
    except Exception as e:
        logger.error(f"Git pack info endpoint error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


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
    global config, oauth_handler, saml_handler

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

    # Initialize SAML handler
    saml_handler = SplunkSAMLAuth()
    logger.info("SAML handler initialized")
    
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