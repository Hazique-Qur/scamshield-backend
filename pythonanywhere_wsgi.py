import sys
import os

# Add the backend directory to path
path = os.path.dirname(os.path.abspath(__file__))
if path not in sys.path:
    sys.path.insert(0, path)

# Change to backend directory
os.chdir(path)

# Import the FastAPI app
from app.main import app as application
