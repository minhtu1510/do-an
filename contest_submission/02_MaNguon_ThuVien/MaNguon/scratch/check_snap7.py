import snap7
try:
    from snap7.types import Areas
    print("Successfully imported Areas from snap7.types")
except ImportError as e:
    print(f"Failed to import from snap7.types: {e}")
    try:
        from snap7.snap7types import Areas
        print("Successfully imported Areas from snap7.snap7types")
    except ImportError as e2:
        print(f"Failed to import from snap7.snap7types: {e2}")

import sys
print(f"Python path: {sys.path}")
try:
    print(f"snap7 file: {snap7.__file__}")
except:
    print("Could not find snap7.__file__")
