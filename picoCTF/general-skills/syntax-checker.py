# This script checks the syntax of a given source code file using a locally running Ollama model.
# Ollama must be installed and 'ollama serve' must be running.

import subprocess
import sys

def check_syntax_with_ollama(code, model="llama3"):
    # Check syntax of source code using a locally running Ollama model.
    # Ollama must be installed and 'ollama serve' must be running.

    prompt = f"Check the following code for syntax and logical errors. \
If there are errors, explain them briefly. If not, say 'No errors found'.\n\nCode:\n{code}"

    try:
        # Run ollama command locally
        result = subprocess.run(
            ["ollama", "run", model, prompt],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print("Error running Ollama:", result.stderr)
            return None
        
        print("\n=== Syntax Check Result ===\n")
        print(result.stdout.strip())

    except FileNotFoundError:
        print("❌ Ollama not found. Please install it from https://ollama.ai and ensure it's running.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python syntax-checker.py <filename>")
        sys.exit(1)

    filename = sys.argv[1]
    try:
        with open(filename, "r", encoding="utf-8") as file:
            source_code = file.read()
    except OSError as exc:
        print(f"❌ Failed to read '{filename}': {exc}")
    else:
        check_syntax_with_ollama(source_code)
