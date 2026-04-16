import sys
import os

# Ensure we can find the server module
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from server import generate_executive_brief

if __name__ == "__main__":
    print("Initiating Commander's Brief synthesis...")
    result = generate_executive_brief()
    print(result)
