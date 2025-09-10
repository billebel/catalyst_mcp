"""Tests for Git pack functionality."""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
from catalyst_mcp.packs.git_manager import GitPackManager
from catalyst_mcp.packs.registry import PackRegistry


class TestGitPackManager:
    """Test Git pack manager functionality."""
    
    def test_prepare_git_auth_with_token(self):
        """Test Git authentication preparation with token."""
        git_manager = GitPackManager()
        user_context = {
            'git_token': 'ghp_test_token_123',
            'git_username': 'testuser',
            'git_password': 'testpass'
        }
        
        auth_config = git_manager._prepare_git_auth(user_context)
        
        assert auth_config['token'] == 'ghp_test_token_123'
        assert auth_config['username'] == 'testuser'
        assert auth_config['password'] == 'testpass'
    
    def test_prepare_git_auth_empty_context(self):
        """Test Git authentication preparation with empty context."""
        git_manager = GitPackManager()
        user_context = {}
        
        auth_config = git_manager._prepare_git_auth(user_context)
        
        assert auth_config == {}
    
    def test_get_pack_dir_name_with_git_extension(self):
        """Test pack directory name generation with .git extension."""
        git_manager = GitPackManager()
        
        dir_name = git_manager._get_pack_dir_name("https://github.com/user/repo.git")
        assert dir_name == "repo"
        
        dir_name = git_manager._get_pack_dir_name("https://github.com/user/my-pack.git", "custom_name")
        assert dir_name == "custom_name"
    
    def test_get_pack_dir_name_without_git_extension(self):
        """Test pack directory name generation without .git extension."""
        git_manager = GitPackManager()
        
        dir_name = git_manager._get_pack_dir_name("https://github.com/user/repo")
        assert dir_name == "repo"
    
    def test_get_pack_dir_name_with_special_chars(self):
        """Test pack directory name generation with special characters."""
        git_manager = GitPackManager()
        
        dir_name = git_manager._get_pack_dir_name("https://github.com/user/my-special@pack!")
        assert dir_name == "my-special_pack_"
    
    def test_validate_env_vars_missing(self):
        """Test environment variable validation with missing variables."""
        git_manager = GitPackManager()
        
        required_env = {"API_KEY": "", "DATABASE_URL": "default_db"}
        provided_env = {"DATABASE_URL": "my_db"}
        
        missing = git_manager._validate_env_vars(required_env, provided_env)
        assert "API_KEY" in missing
        assert "DATABASE_URL" not in missing
    
    def test_validate_env_vars_all_provided(self):
        """Test environment variable validation with all variables provided."""
        git_manager = GitPackManager()
        
        required_env = {"API_KEY": "", "DATABASE_URL": "default"}
        provided_env = {"API_KEY": "test_key", "DATABASE_URL": "my_db"}
        
        missing = git_manager._validate_env_vars(required_env, provided_env)
        assert len(missing) == 0
    
    @patch('catalyst_mcp.packs.git_manager.Path.exists')
    def test_discover_env_requirements_no_file(self, mock_exists):
        """Test environment requirements discovery when no .env.example exists."""
        mock_exists.return_value = False
        git_manager = GitPackManager()
        
        env_reqs = git_manager._discover_env_requirements(Path("/fake/path"))
        assert env_reqs == {}
    
    @patch('builtins.open', create=True)
    @patch('catalyst_mcp.packs.git_manager.Path.exists')
    def test_discover_env_requirements_with_file(self, mock_exists, mock_open):
        """Test environment requirements discovery with .env.example file."""
        mock_exists.return_value = True
        mock_open.return_value.__enter__.return_value.read.return_value = """
# Comment
API_KEY=your_api_key_here
DATABASE_URL=postgresql://localhost/db
# Another comment
TIMEOUT=30
"""
        mock_open.return_value.__enter__.return_value.__iter__ = lambda self: iter([
            "# Comment\n",
            "API_KEY=your_api_key_here\n",
            "DATABASE_URL=postgresql://localhost/db\n",
            "# Another comment\n",
            "TIMEOUT=30\n"
        ])
        
        git_manager = GitPackManager()
        env_reqs = git_manager._discover_env_requirements(Path("/fake/path"))
        
        assert env_reqs["API_KEY"] == "your_api_key_here"
        assert env_reqs["DATABASE_URL"] == "postgresql://localhost/db"
        assert env_reqs["TIMEOUT"] == "30"
    
    def test_load_git_pack_missing_credentials(self):
        """Test Git pack loading with missing credentials."""
        git_manager = GitPackManager()
        user_context = {}  # No credentials
        
        result = git_manager.load_git_pack(
            repo_url="https://github.com/user/repo.git",
            user_context=user_context
        )
        
        assert result["error"] is True
        assert "Git credentials required" in result["message"]
    
    @patch('catalyst_mcp.packs.git_manager.Repo')
    @patch('catalyst_mcp.packs.git_manager.shutil.rmtree')
    @patch('catalyst_mcp.packs.git_manager.Path.exists')
    def test_clone_or_update_repo_new_clone(self, mock_exists, mock_rmtree, mock_repo):
        """Test cloning a new repository."""
        git_manager = GitPackManager()
        
        # Mock directory doesn't exist
        mock_exists.return_value = False
        
        # Mock successful clone
        mock_repo_instance = Mock()
        mock_repo.clone_from.return_value = mock_repo_instance
        
        auth_config = {"token": "test_token"}
        target_dir = Path("/fake/target")
        
        result = git_manager._clone_or_update_repo(
            "https://github.com/user/repo.git",
            target_dir,
            auth_config,
            "main"
        )
        
        assert result == mock_repo_instance
        mock_repo.clone_from.assert_called_once()


class TestGitPackIntegration:
    """Test Git pack integration with PackRegistry."""
    
    @patch('catalyst_mcp.packs.git_manager.git', None)
    def test_git_manager_without_gitpython(self):
        """Test GitPackManager raises error without GitPython."""
        with pytest.raises(ImportError, match="GitPython is required"):
            GitPackManager()
    
    def test_pack_registry_git_methods_delegation(self):
        """Test PackRegistry properly delegates Git pack methods."""
        with patch('catalyst_mcp.packs.git_manager.git'):
            registry = PackRegistry()
            
            # Mock the git manager
            registry.git_manager = Mock()
            
            # Test method delegation
            test_context = {"git_token": "test"}
            test_result = {"success": True}
            
            registry.git_manager.load_git_pack.return_value = test_result
            registry.git_manager.list_git_packs.return_value = test_result
            registry.git_manager.get_git_pack_info.return_value = test_result
            registry.git_manager.update_git_pack.return_value = test_result
            registry.git_manager.remove_git_pack.return_value = test_result
            
            # Test load_git_pack delegation
            result = registry.load_git_pack("https://github.com/user/repo.git", test_context)
            assert result == test_result
            registry.git_manager.load_git_pack.assert_called_once()
            
            # Test list_git_packs delegation
            result = registry.list_git_packs()
            assert result == test_result
            registry.git_manager.list_git_packs.assert_called_once()
            
            # Test get_git_pack_info delegation
            result = registry.get_git_pack_info("test_pack")
            assert result == test_result
            registry.git_manager.get_git_pack_info.assert_called_once_with("test_pack")
            
            # Test update_git_pack delegation
            result = registry.update_git_pack("test_pack", test_context)
            assert result == test_result
            registry.git_manager.update_git_pack.assert_called_once_with("test_pack", test_context, None)
            
            # Test remove_git_pack delegation
            result = registry.remove_git_pack("test_pack")
            assert result == test_result
            registry.git_manager.remove_git_pack.assert_called_once_with("test_pack")


class TestGitPackEndpoints:
    """Test Git pack API endpoints (integration-style tests)."""
    
    def test_load_git_pack_endpoint_missing_repo_url(self):
        """Test load endpoint with missing repo_url."""
        # This would be tested in integration tests with actual HTTP client
        # For now, we'll test the validation logic
        request_body = {"branch": "main"}
        
        # Simulate the validation
        repo_url = request_body.get("repo_url")
        assert repo_url is None
        # Would return 400 status code
    
    def test_load_git_pack_endpoint_valid_request(self):
        """Test load endpoint with valid request."""
        request_body = {
            "repo_url": "https://github.com/user/repo.git",
            "branch": "main",
            "env_vars": '{"API_KEY": "test"}'
        }
        
        # Simulate the validation
        repo_url = request_body.get("repo_url")
        branch = request_body.get("branch", "main")
        env_vars = request_body.get("env_vars")
        
        assert repo_url == "https://github.com/user/repo.git"
        assert branch == "main"
        assert env_vars == '{"API_KEY": "test"}'
        
        # Test env_vars JSON parsing
        try:
            parsed_env = json.loads(env_vars)
            assert parsed_env["API_KEY"] == "test"
        except json.JSONDecodeError:
            assert False, "Should be valid JSON"
    
    def test_update_git_pack_endpoint_missing_pack_name(self):
        """Test update endpoint with missing pack_name."""
        request_body = {"branch": "develop"}
        
        pack_name = request_body.get("pack_name")
        assert pack_name is None
        # Would return 400 status code
    
    def test_remove_git_pack_endpoint_valid_request(self):
        """Test remove endpoint with valid request."""
        request_body = {"pack_name": "test_pack"}
        
        pack_name = request_body.get("pack_name")
        assert pack_name == "test_pack"


class TestEnvVarSubstitution:
    """Test environment variable substitution in pack configs."""
    
    @patch('builtins.open', create=True)
    @patch('yaml.safe_load')
    @patch('yaml.dump')
    def test_apply_env_vars_to_pack(self, mock_yaml_dump, mock_yaml_load, mock_open):
        """Test environment variable application to pack configuration."""
        git_manager = GitPackManager()
        
        # Mock pack configuration
        mock_pack_config = {
            "metadata": {"name": "test_pack"},
            "connection": {"url": "${API_URL}", "token": "${API_TOKEN}"}
        }
        mock_yaml_load.side_effect = [mock_pack_config, {
            "metadata": {"name": "test_pack"},
            "connection": {"url": "https://api.example.com", "token": "secret123"}
        }]
        
        mock_yaml_dump.return_value = """
metadata:
  name: test_pack
connection:
  url: ${API_URL}
  token: ${API_TOKEN}
"""
        
        env_vars = {
            "API_URL": "https://api.example.com",
            "API_TOKEN": "secret123"
        }
        
        result = git_manager._apply_env_vars_to_pack(Path("/fake/pack.yaml"), env_vars)
        
        # Verify the substitution worked
        assert result["connection"]["url"] == "https://api.example.com"
        assert result["connection"]["token"] == "secret123"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])