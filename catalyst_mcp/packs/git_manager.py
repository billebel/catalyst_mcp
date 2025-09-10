"""Git pack manager for loading MCP packs from Git repositories."""

import os
import json
import shutil
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timezone

try:
    import git
    from git import Repo, InvalidGitRepositoryError, GitCommandError
except ImportError:
    git = None
    Repo = None
    InvalidGitRepositoryError = Exception
    GitCommandError = Exception

from catalyst_pack_schemas import PackValidator, Pack
from .loader import PackLoader
from .models import PackValidationError

logger = logging.getLogger(__name__)


class GitPackManager:
    """Manages Git-based pack loading with user credentials."""
    
    def __init__(self, git_packs_dir: str = "git-packs"):
        """Initialize Git pack manager.
        
        Args:
            git_packs_dir: Directory to store cloned Git repositories
        """
        if git is None:
            raise ImportError("GitPython is required for Git pack loading. Install with: pip install GitPython")
            
        self.git_packs_dir = Path(git_packs_dir)
        self.git_packs_dir.mkdir(exist_ok=True)
        self.pack_loader = PackLoader()
        self.validator = PackValidator()
        self.loaded_git_packs: Dict[str, Dict[str, Any]] = {}
        
    def _get_pack_dir_name(self, repo_url: str, pack_name: Optional[str] = None) -> str:
        """Generate a unique directory name for the Git pack."""
        if pack_name:
            return pack_name
            
        # Extract repo name from URL
        if repo_url.endswith('.git'):
            repo_name = repo_url.split('/')[-1][:-4]  # Remove .git
        else:
            repo_name = repo_url.split('/')[-1]
        
        # Clean the name for filesystem use
        import re
        clean_name = re.sub(r'[^\w\-_]', '_', repo_name)
        return clean_name
    
    def _prepare_git_auth(self, user_context: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare Git authentication from user context."""
        auth_config = {}
        
        # GitHub/GitLab token (preferred)
        if git_token := user_context.get('git_token'):
            auth_config['token'] = git_token
            
        # Username/password
        if git_username := user_context.get('git_username'):
            auth_config['username'] = git_username
            
        if git_password := user_context.get('git_password'):
            auth_config['password'] = git_password
            
        return auth_config
    
    def _clone_or_update_repo(self, repo_url: str, target_dir: Path, 
                             auth_config: Dict[str, Any], branch: str = "main") -> Repo:
        """Clone or update Git repository with authentication."""
        try:
            # Prepare authenticated URL for HTTPS
            if repo_url.startswith('https://') and 'token' in auth_config:
                # Use token authentication for GitHub/GitLab
                auth_url = repo_url.replace('https://', f'https://{auth_config["token"]}@')
            elif repo_url.startswith('https://') and 'username' in auth_config and 'password' in auth_config:
                # Use username/password authentication
                auth_url = repo_url.replace('https://', f'https://{auth_config["username"]}:{auth_config["password"]}@')
            else:
                # Use URL as-is (SSH or public repo)
                auth_url = repo_url
            
            if target_dir.exists() and (target_dir / '.git').exists():
                # Update existing repository
                logger.info(f"Updating existing Git pack repository: {target_dir}")
                repo = Repo(target_dir)
                
                # Fetch latest changes
                origin = repo.remotes.origin
                origin.fetch()
                
                # Checkout and pull specified branch
                if branch not in [b.name for b in repo.branches]:
                    # Create local branch tracking remote
                    repo.git.checkout('-b', branch, f'origin/{branch}')
                else:
                    repo.git.checkout(branch)
                    repo.git.pull('origin', branch)
                    
                return repo
            else:
                # Clone new repository
                logger.info(f"Cloning Git pack repository: {repo_url} -> {target_dir}")
                if target_dir.exists():
                    shutil.rmtree(target_dir)
                
                repo = Repo.clone_from(auth_url, target_dir, branch=branch)
                return repo
                
        except (GitCommandError, InvalidGitRepositoryError) as e:
            logger.error(f"Git operation failed: {e}")
            raise ValueError(f"Failed to access Git repository: {str(e)}")
    
    def _discover_env_requirements(self, repo_dir: Path) -> Dict[str, str]:
        """Discover environment variable requirements from repository."""
        env_requirements = {}
        
        # Check for .env.example file
        env_example = repo_dir / ".env.example"
        if env_example.exists():
            try:
                with open(env_example, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            key, value = line.split('=', 1)
                            env_requirements[key] = value
            except Exception as e:
                logger.warning(f"Failed to parse .env.example: {e}")
                
        return env_requirements
    
    def _validate_env_vars(self, required_env: Dict[str, str], provided_env: Dict[str, str]) -> List[str]:
        """Validate that required environment variables are provided."""
        missing_vars = []
        for key, default_value in required_env.items():
            if key not in provided_env and not default_value:
                missing_vars.append(key)
        return missing_vars
    
    def _find_pack_yaml(self, repo_dir: Path, pack_path: Optional[str] = None) -> Path:
        """Find pack.yaml in repository."""
        if pack_path:
            pack_yaml = repo_dir / pack_path / "pack.yaml"
        else:
            pack_yaml = repo_dir / "pack.yaml"
            
        if not pack_yaml.exists():
            raise PackValidationError(f"pack.yaml not found at {pack_yaml}")
            
        return pack_yaml
    
    def _apply_env_vars_to_pack(self, pack_yaml_path: Path, env_vars: Dict[str, str]) -> Dict[str, Any]:
        """Load pack YAML and apply environment variable substitution."""
        import yaml
        
        with open(pack_yaml_path, 'r', encoding='utf-8') as f:
            pack_config = yaml.safe_load(f)
        
        # Apply environment variables to the pack configuration
        pack_config_str = yaml.dump(pack_config)
        
        # Simple environment variable substitution
        for key, value in env_vars.items():
            pack_config_str = pack_config_str.replace(f"${{{key}}}", value)
            pack_config_str = pack_config_str.replace(f"${key}", value)
            
        return yaml.safe_load(pack_config_str)
    
    def load_git_pack(self, repo_url: str, user_context: Dict[str, Any], 
                     pack_path: Optional[str] = None, env_vars: Optional[str] = None,
                     branch: str = "main", pack_name: Optional[str] = None) -> Dict[str, Any]:
        """Load a pack from a Git repository.
        
        Args:
            repo_url: Git repository URL
            user_context: User authentication context with Git credentials
            pack_path: Optional subdirectory path in repo
            env_vars: JSON string of environment variables
            branch: Git branch to clone
            pack_name: Optional pack name override
            
        Returns:
            Result dictionary with success/error information
        """
        try:
            # Prepare Git authentication
            auth_config = self._prepare_git_auth(user_context)
            if not auth_config:
                return {
                    "error": True,
                    "message": "Git credentials required. Provide X-Git-Token, or X-Git-Username/X-Git-Password headers."
                }
            
            # Determine pack directory name
            dir_name = self._get_pack_dir_name(repo_url, pack_name)
            target_dir = self.git_packs_dir / dir_name
            
            # Clone or update repository
            repo = self._clone_or_update_repo(repo_url, target_dir, auth_config, branch)
            
            # Find pack.yaml
            pack_yaml_path = self._find_pack_yaml(target_dir, pack_path)
            
            # Discover environment requirements
            env_requirements = self._discover_env_requirements(target_dir)
            
            # Parse provided environment variables
            provided_env = {}
            if env_vars:
                try:
                    provided_env = json.loads(env_vars)
                except json.JSONDecodeError as e:
                    return {"error": True, "message": f"Invalid env_vars JSON: {str(e)}"}
            
            # Validate environment variables
            missing_vars = self._validate_env_vars(env_requirements, provided_env)
            if missing_vars:
                return {
                    "error": True,
                    "message": f"Missing required environment variables: {missing_vars}",
                    "required_vars": list(env_requirements.keys()),
                    "template": env_requirements
                }
            
            # Apply environment variables and load pack
            if provided_env:
                pack_config = self._apply_env_vars_to_pack(pack_yaml_path, provided_env)
                # Create temporary pack file with env vars applied
                temp_pack_path = target_dir / "pack_with_env.yaml"
                import yaml
                with open(temp_pack_path, 'w', encoding='utf-8') as f:
                    yaml.dump(pack_config, f)
                pack_yaml_path = temp_pack_path
            
            # Load and validate pack
            pack = self.pack_loader.load_pack_from_file(str(pack_yaml_path))
            if not pack:
                return {"error": True, "message": "Failed to load pack configuration"}
            
            # Store Git pack metadata
            git_commit = repo.head.commit
            self.loaded_git_packs[pack.metadata.name] = {
                "name": pack.metadata.name,
                "repo_url": repo_url,
                "branch": branch,
                "pack_path": pack_path,
                "target_dir": str(target_dir),
                "env_vars": provided_env,
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "status": "loaded",
                "tools_count": len(pack.tools),
                "git_info": {
                    "commit_hash": git_commit.hexsha[:8],
                    "commit_message": git_commit.message.strip(),
                    "author": git_commit.author.name
                }
            }
            
            logger.info(f"Successfully loaded Git pack: {pack.metadata.name}")
            return {
                "success": True,
                "pack_name": pack.metadata.name,
                "tools_loaded": len(pack.tools),
                "prompts_loaded": len(pack.prompts),
                "commit_hash": git_commit.hexsha[:8]
            }
            
        except Exception as e:
            logger.error(f"Failed to load Git pack from {repo_url}: {e}")
            return {"error": True, "message": f"Failed to load Git pack: {str(e)}"}
    
    def list_git_packs(self) -> Dict[str, Any]:
        """List all loaded Git packs."""
        return {"packs": list(self.loaded_git_packs.values())}
    
    def get_git_pack_info(self, pack_name: str) -> Dict[str, Any]:
        """Get detailed information about a Git pack."""
        if pack_name not in self.loaded_git_packs:
            return {"error": True, "message": f"Git pack '{pack_name}' not found"}
        
        return self.loaded_git_packs[pack_name]
    
    def update_git_pack(self, pack_name: str, user_context: Dict[str, Any], 
                       branch: Optional[str] = None) -> Dict[str, Any]:
        """Update an existing Git pack."""
        if pack_name not in self.loaded_git_packs:
            return {"error": True, "message": f"Git pack '{pack_name}' not found"}
        
        pack_info = self.loaded_git_packs[pack_name]
        return self.load_git_pack(
            repo_url=pack_info["repo_url"],
            user_context=user_context,
            pack_path=pack_info.get("pack_path"),
            env_vars=json.dumps(pack_info.get("env_vars", {})),
            branch=branch or pack_info["branch"],
            pack_name=pack_name
        )
    
    def remove_git_pack(self, pack_name: str) -> Dict[str, Any]:
        """Remove a Git pack from runtime."""
        if pack_name not in self.loaded_git_packs:
            return {"error": True, "message": f"Git pack '{pack_name}' not found"}
        
        pack_info = self.loaded_git_packs[pack_name]
        target_dir = Path(pack_info["target_dir"])
        
        try:
            # Remove from loaded packs
            del self.loaded_git_packs[pack_name]
            
            # Remove directory
            if target_dir.exists():
                shutil.rmtree(target_dir)
            
            logger.info(f"Successfully removed Git pack: {pack_name}")
            return {"success": True, "message": f"Git pack '{pack_name}' removed"}
            
        except Exception as e:
            logger.error(f"Failed to remove Git pack {pack_name}: {e}")
            return {"error": True, "message": f"Failed to remove Git pack: {str(e)}"}