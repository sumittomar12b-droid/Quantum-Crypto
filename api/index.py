"""
Vercel Serverless Function Entrypoint.
Routes all incoming HTTP requests to FastAPI application.
"""

import sys
import os

# Add project root directory to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from web.app import app

# Vercel looks for the ASGI/WSGI 'app' variable
