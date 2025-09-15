"""Simple OAuth handler for MCP server."""

import asyncio
import secrets
import hashlib
import base64
from typing import Dict, Optional
from datetime import datetime, timedelta
import httpx
from urllib.parse import urlencode

class SimpleOAuth:
    """Minimal OAuth 2.1 with PKCE implementation."""

    def __init__(self):
        self.pending_auth = {}  # state -> auth_info
        self.tokens = {}  # instance_url -> token_data

    def generate_pkce(self) -> tuple[str, str]:
        """Generate PKCE challenge and verifier."""
        verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).decode('utf-8').rstrip('=')
        return verifier, challenge

    async def start_auth_flow(self, instance_url: str, client_id: str, redirect_uri: str = "http://localhost:8443/callback") -> Dict:
        """Start OAuth flow for a Splunk instance."""
        state = secrets.token_urlsafe(32)
        verifier, challenge = self.generate_pkce()

        # Store auth state
        self.pending_auth[state] = {
            "instance_url": instance_url,
            "verifier": verifier,
            "client_id": client_id,
            "redirect_uri": redirect_uri
        }

        # Build authorization URL
        auth_params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "search admin"
        }

        auth_url = f"{instance_url}/services/auth/authorize?{urlencode(auth_params)}"

        return {
            "auth_url": auth_url,
            "state": state,
            "message": "Please visit the auth_url to authenticate"
        }

    async def handle_callback(self, code: str, state: str) -> Dict:
        """Handle OAuth callback with authorization code."""
        if state not in self.pending_auth:
            return {"error": "Invalid state"}

        auth_info = self.pending_auth.pop(state)

        # Exchange code for token
        async with httpx.AsyncClient(verify=False) as client:
            token_response = await client.post(
                f"{auth_info['instance_url']}/services/auth/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "client_id": auth_info['client_id'],
                    "redirect_uri": auth_info['redirect_uri'],
                    "code_verifier": auth_info['verifier']
                }
            )

        if token_response.status_code == 200:
            token_data = token_response.json()
            # Store token for this instance
            self.tokens[auth_info['instance_url']] = {
                "access_token": token_data["access_token"],
                "refresh_token": token_data.get("refresh_token"),
                "expires_at": datetime.now() + timedelta(seconds=token_data.get("expires_in", 3600))
            }
            return {"status": "success", "instance": auth_info['instance_url']}

        return {"error": "Token exchange failed"}

    def get_token(self, instance_url: str) -> Optional[str]:
        """Get valid token for an instance."""
        if instance_url in self.tokens:
            token_data = self.tokens[instance_url]
            if token_data["expires_at"] > datetime.now():
                return token_data["access_token"]
        return None

    def requires_auth(self, instance_url: str) -> bool:
        """Check if instance needs authentication."""
        return self.get_token(instance_url) is None