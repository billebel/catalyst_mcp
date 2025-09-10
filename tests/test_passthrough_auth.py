#!/usr/bin/env python3
"""
Test passthrough authentication implementation.
Following TDD: These tests should FAIL initially, then PASS after implementation.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from contextvars import ContextVar
from starlette.requests import Request
from starlette.responses import Response

# Import the modules we'll be testing
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from catalyst_mcp.packs.adapters.api_adapter import AuthenticationHandler
from catalyst_pack_schemas import AuthMethod, ConnectionConfig, AuthConfig


class TestUserContextExtraction:
    """Test user context extraction from HTTP headers."""
    
    def test_user_context_exists(self):
        """Test that user_context ContextVar is defined."""
        # This should FAIL - user_context not defined yet
        from catalyst_mcp.main import user_context
        assert user_context is not None
        assert isinstance(user_context, ContextVar)

    @pytest.mark.asyncio
    async def test_auth_middleware_extracts_bearer_token(self):
        """Test middleware extracts Bearer token from Authorization header."""
        # Mock request with Authorization header
        mock_request = Mock(spec=Request)
        mock_request.headers = {"authorization": "Bearer user-token-123"}
        
        # Mock next handler
        async def mock_next(request):
            return Response("OK")
        
        # This should FAIL - auth_middleware not implemented yet
        from catalyst_mcp.main import auth_middleware
        
        # Execute middleware
        response = await auth_middleware(mock_request, mock_next)
        
        # Verify user context was set
        from catalyst_mcp.main import user_context
        context = user_context.get({})
        assert context.get("token") == "user-token-123"
        assert context.get("headers", {}).get("Authorization") == "Bearer user-token-123"

    @pytest.mark.asyncio 
    async def test_auth_middleware_handles_missing_auth(self):
        """Test middleware handles requests without Authorization header."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {}
        
        async def mock_next(request):
            return Response("OK")
        
        # This should FAIL - auth_middleware not implemented yet
        from catalyst_mcp.main import auth_middleware
        
        response = await auth_middleware(mock_request, mock_next)
        
        # Verify user context is empty
        from catalyst_mcp.main import user_context
        context = user_context.get({})
        assert context == {}


class TestPassthroughAuthenticationHandler:
    """Test passthrough authentication in API adapter."""
    
    def test_prepare_auth_supports_passthrough(self):
        """Test that prepare_auth handles PASSTHROUGH auth method."""
        # Create connection config with passthrough auth
        auth_config = AuthConfig(
            method=AuthMethod.PASSTHROUGH,
            config={
                "source": "user_context",
                "header": "Authorization", 
                "format": "Bearer {token}"
            }
        )
        
        connection = ConnectionConfig(
            type="rest",
            base_url="https://api.example.com",
            auth=auth_config
        )
        
        # Mock user context
        mock_user_context = {
            "token": "user-token-123",
            "headers": {"Authorization": "Bearer user-token-123"}
        }
        
        # This should FAIL - passthrough support not implemented yet
        result = AuthenticationHandler.prepare_auth(connection, mock_user_context)
        
        # Should return headers with user token
        expected = {"headers": {"Authorization": "Bearer user-token-123"}}
        assert result == expected

    def test_prepare_auth_passthrough_with_custom_format(self):
        """Test passthrough auth with custom token format."""
        auth_config = AuthConfig(
            method=AuthMethod.PASSTHROUGH,
            config={
                "source": "user_context",
                "header": "X-API-Token",
                "format": "Token {token}"
            }
        )
        
        connection = ConnectionConfig(
            type="rest",
            base_url="https://api.example.com", 
            auth=auth_config
        )
        
        mock_user_context = {
            "token": "abc123",
            "headers": {"Authorization": "Bearer abc123"}
        }
        
        # This should FAIL - custom format not implemented yet
        result = AuthenticationHandler.prepare_auth(connection, mock_user_context)
        
        expected = {"headers": {"X-API-Token": "Token abc123"}}
        assert result == expected

    def test_prepare_auth_passthrough_missing_user_context(self):
        """Test passthrough auth when user context is missing."""
        auth_config = AuthConfig(
            method=AuthMethod.PASSTHROUGH,
            config={"source": "user_context"}
        )
        
        connection = ConnectionConfig(
            type="rest",
            base_url="https://api.example.com",
            auth=auth_config
        )
        
        # This should FAIL - error handling not implemented yet
        with pytest.raises(ValueError, match="User context required for passthrough authentication"):
            AuthenticationHandler.prepare_auth(connection, None)

    def test_prepare_auth_passthrough_missing_token(self):
        """Test passthrough auth when user context lacks token."""
        auth_config = AuthConfig(
            method=AuthMethod.PASSTHROUGH,
            config={"source": "user_context"}
        )
        
        connection = ConnectionConfig(
            type="rest", 
            base_url="https://api.example.com",
            auth=auth_config
        )
        
        mock_user_context = {}  # No token
        
        # This should FAIL - token validation not implemented yet
        with pytest.raises(ValueError, match="No authentication token found in user context"):
            AuthenticationHandler.prepare_auth(connection, mock_user_context)


class TestToolExecutionWithPassthrough:
    """Test tool execution with user credential forwarding."""
    
    @pytest.mark.asyncio
    async def test_api_adapter_uses_user_context_for_passthrough(self):
        """Test that API adapter gets user context during tool execution."""
        from catalyst_mcp.packs.adapters.api_adapter import APIAdapter
        from catalyst_mcp.main import user_context
        from catalyst_pack_schemas import (
            Pack, PackMetadata, ConnectionConfig, AuthConfig, 
            ToolDefinition, ParameterDefinition, AuthMethod
        )
        
        # Set up user context
        mock_user_context = {
            "token": "user-token-789",
            "headers": {"Authorization": "Bearer user-token-789"}
        }
        user_context.set(mock_user_context)
        
        # Create proper schema objects
        metadata = PackMetadata(
            name="test_pack",
            version="1.0.0", 
            description="Test pack",
            vendor="test",
            license="MIT",
            compatibility="test",
            domain="test"
        )
        
        auth_config = AuthConfig(
            method=AuthMethod.PASSTHROUGH,
            config={"source": "user_context"}
        )
        
        connection = ConnectionConfig(
            type="rest",
            base_url="https://api.example.com",
            auth=auth_config
        )
        
        tool_def = ToolDefinition(
            name="test_tool",
            type="list",
            description="Test tool",
            endpoint="/test",
            method="GET",
            parameters=[]
        )
        
        # Create pack
        pack = Pack(
            metadata=metadata,
            connection=connection,
            tools={"test_tool": tool_def}
        )
        
        # Create API adapter
        adapter = APIAdapter(pack)
        
        # Mock the HTTP request to check auth headers
        with patch('httpx.AsyncClient.request') as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"result": "success"}
            mock_response.headers = {}
            mock_request.return_value = mock_response
            
            # Create tool definition
            tool_def = ToolDefinition(
                name="test_tool",
                type="list",
                description="Test tool",
                endpoint="/test",
                method="GET",
                parameters=[]
            )
            
            # Execute tool - this should FAIL until integration is complete
            result = await adapter.execute_tool(tool_def, {})
            
            # Verify the request was made with user credentials
            mock_request.assert_called_once()
            call_args = mock_request.call_args
            
            # Check that Authorization header contains user token
            headers = call_args.kwargs.get('headers', {})
            assert 'Authorization' in headers
            assert headers['Authorization'] == 'Bearer user-token-789'


if __name__ == "__main__":
    # Run tests with verbose output
    pytest.main([__file__, "-v", "--tb=short"])