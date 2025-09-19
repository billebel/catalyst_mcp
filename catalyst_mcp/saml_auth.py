"""SAML authentication handler for Splunk instances."""

import asyncio
import secrets
import json
from typing import Dict, Optional
from datetime import datetime, timedelta
import httpx
from urllib.parse import urlencode, urlparse

class SplunkSAMLAuth:
    """Handle SAML/SSO authentication for Splunk instances."""

    def __init__(self):
        self.pending_auth = {}  # state -> auth_info
        self.tokens = {}  # instance_url -> token_data

    async def detect_auth_method(self, splunk_url: str) -> str:
        """Auto-detect if Splunk instance uses SAML authentication.

        Args:
            splunk_url: Splunk instance URL

        Returns:
            "saml" if SAML detected, "basic" otherwise
        """
        try:
            async with httpx.AsyncClient(follow_redirects=False, verify=False, timeout=10) as client:
                # Check login page for SAML redirect
                response = await client.get(f"{splunk_url}/en-US/account/login")

                # If redirected to external SSO, it's SAML
                if response.status_code == 302:
                    redirect_url = response.headers.get("Location", "")
                    parsed_redirect = urlparse(redirect_url)
                    parsed_splunk = urlparse(splunk_url)

                    # Redirect to different domain = SAML
                    if parsed_redirect.netloc != parsed_splunk.netloc:
                        return "saml"

                # Check for SAML endpoints
                saml_endpoints = [
                    "/saml/acs",
                    "/services/auth/saml",
                    "/sso"
                ]

                for endpoint in saml_endpoints:
                    try:
                        saml_response = await client.get(f"{splunk_url}{endpoint}")
                        # 200 or 405 (method not allowed) means endpoint exists
                        if saml_response.status_code in [200, 405]:
                            return "saml"
                    except:
                        continue

                # Check for SSO indicators in login page content
                if response.status_code == 200:
                    content = response.text.lower()
                    saml_indicators = ["sso", "single sign", "saml", "identity provider"]
                    if any(indicator in content for indicator in saml_indicators):
                        return "saml"

        except Exception as e:
            # If detection fails, assume basic auth
            pass

        return "basic"

    async def start_saml_flow(self, splunk_url: str) -> Dict:
        """Start SAML authentication flow.

        Args:
            splunk_url: Splunk instance URL

        Returns:
            Authentication flow information
        """
        # Generate state for security
        state = secrets.token_urlsafe(32)

        # Store auth state
        self.pending_auth[state] = {
            "splunk_url": splunk_url,
            "timestamp": datetime.now(),
            "attempts": 0
        }

        # Create auth URL that will trigger SAML flow
        # We redirect to a page that will attempt token creation
        auth_url = f"http://localhost:8443/saml/start?state={state}&splunk_url={splunk_url}"

        return {
            "auth_url": auth_url,
            "state": state,
            "instructions": "Please visit this URL to authenticate via your organization's SSO",
            "callback_url": "http://localhost:8443/saml/callback",
            "method": "saml"
        }

    def get_token(self, splunk_url: str) -> Optional[str]:
        """Get stored SAML token for an instance.

        Args:
            splunk_url: Splunk instance URL

        Returns:
            Valid token or None
        """
        if splunk_url in self.tokens:
            token_data = self.tokens[splunk_url]
            if token_data["expires_at"] > datetime.now():
                return token_data["access_token"]
            else:
                # Token expired, remove it
                del self.tokens[splunk_url]
        return None

    def requires_auth(self, splunk_url: str) -> bool:
        """Check if instance needs authentication.

        Args:
            splunk_url: Splunk instance URL

        Returns:
            True if authentication needed
        """
        return self.get_token(splunk_url) is None

    def store_token(self, splunk_url: str, token: str, expires_in: int = 2592000) -> None:
        """Store authentication token for instance.

        Args:
            splunk_url: Splunk instance URL
            token: Authentication token
            expires_in: Token expiration in seconds (default 30 days)
        """
        self.tokens[splunk_url] = {
            "access_token": token,
            "token_type": "Splunk",
            "expires_at": datetime.now() + timedelta(seconds=expires_in),
            "auth_method": "saml",
            "created_at": datetime.now()
        }

    def get_pending_auth(self, state: str) -> Optional[Dict]:
        """Get and remove pending auth by state.

        Args:
            state: Auth state parameter

        Returns:
            Auth info or None
        """
        return self.pending_auth.pop(state, None)

    def cleanup_expired_auth(self) -> None:
        """Clean up expired pending auth attempts."""
        cutoff = datetime.now() - timedelta(minutes=15)  # 15 minute timeout
        expired_states = [
            state for state, info in self.pending_auth.items()
            if info["timestamp"] < cutoff
        ]
        for state in expired_states:
            del self.pending_auth[state]

    def get_auth_status(self, splunk_url: str) -> Dict:
        """Get authentication status for instance.

        Args:
            splunk_url: Splunk instance URL

        Returns:
            Status information
        """
        token_data = self.tokens.get(splunk_url)

        if token_data:
            return {
                "authenticated": True,
                "instance": splunk_url,
                "auth_method": "saml",
                "expires_at": token_data["expires_at"].isoformat(),
                "created_at": token_data["created_at"].isoformat()
            }
        else:
            return {
                "authenticated": False,
                "instance": splunk_url,
                "message": "Not authenticated - use SAML authentication flow"
            }

    def list_authenticated_instances(self) -> Dict:
        """List all authenticated instances.

        Returns:
            Dictionary of authenticated instances and their status
        """
        instances = {}
        current_time = datetime.now()

        for url, token_data in self.tokens.items():
            is_valid = token_data["expires_at"] > current_time
            instances[url] = {
                "authenticated": is_valid,
                "expires_at": token_data["expires_at"].isoformat(),
                "auth_method": "saml"
            }

        return instances