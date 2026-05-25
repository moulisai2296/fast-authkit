import os
import ast
import sys
import pytest
from unittest.mock import patch
from authkit_fastapi.cli import bootstrap_project

def test_cli_bootstrap_success(tmp_path):
    # Change working directory to a temp path for isolated generation
    original_cwd = os.getcwd()
    os.chdir(tmp_path)
    
    try:
        # Execute the bootstrap command logic
        bootstrap_project()
        
        # Verify directories
        assert os.path.exists("auth")
        assert os.path.isdir("auth")
        
        # Verify files created
        expected_files = [
            "auth/__init__.py",
            "auth/models.py",
            "auth/schemas.py",
            "auth/setup.py",
            ".env",
            ".env.example"
        ]
        for file in expected_files:
            assert os.path.exists(file), f"File {file} was not created"
            assert os.path.isfile(file)
            
        # Verify generated environment files have configurations
        with open(".env", "r", encoding="utf-8") as f:
            env_content = f.read()
            assert "AUTHKIT_SECRET_KEY=" in env_content
            assert "AUTHKIT_DATABASE_URL=sqlite+aiosqlite:///./authkit.db" in env_content

        # Verify that all generated python code files are syntactically valid
        python_files = [
            "auth/__init__.py",
            "auth/models.py",
            "auth/schemas.py",
            "auth/setup.py"
        ]
        for py_file in python_files:
            with open(py_file, "r", encoding="utf-8") as f:
                code = f.read()
                # ast.parse raises SyntaxError if syntax is invalid
                ast.parse(code)

    finally:
        # Restore directory state
        os.chdir(original_cwd)

def test_cli_bootstrap_does_not_overwrite(tmp_path):
    original_cwd = os.getcwd()
    os.chdir(tmp_path)
    
    try:
        # Pre-create a file in the workspace
        os.makedirs("auth")
        with open("auth/models.py", "w", encoding="utf-8") as f:
            f.write("# Existing content")
            
        # Run bootstrap
        bootstrap_project()
        
        # Verify models.py was not overwritten
        with open("auth/models.py", "r", encoding="utf-8") as f:
            content = f.read()
            assert content == "# Existing content"
            
    finally:
        os.chdir(original_cwd)
