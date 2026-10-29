import io
import json
import os
import sys

# Bounds for one decoder run. app.py also enforces a deadline and reads at most
# MAX_OUTPUT_BYTES of the child's output.
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MEMORY_LIMIT_BYTES = 1024 * 1024 * 1024

LEGACY = '--legacy' in sys.argv
if LEGACY:
    sys.argv.remove('--legacy')
    # Colorama strips ANSI colors unless stdout looks like a terminal, and the
    # legacy view renders those colors.
    sys.stdout.isatty = lambda: True


def apply_resource_limits():
    try:
        import resource
    except ImportError:  # Windows development hosts have no rlimits.
        return
    try:
        resource.setrlimit(resource.RLIMIT_AS, (MEMORY_LIMIT_BYTES, MEMORY_LIMIT_BYTES))
    except (ValueError, OSError):
        pass


class OutputLimitExceeded(Exception):
    pass


class BoundedOutput(io.StringIO):
    """Collects report text and stops the decoder once the budget is spent."""

    def __init__(self, limit):
        super().__init__()
        self.limit = limit
        self.size = 0

    def write(self, s):
        self.size += len(s)
        if self.size > self.limit:
            raise OutputLimitExceeded()
        return super().write(s)

    def isatty(self):
        return LEGACY


# Import the official script as a module
try:
    import decode_spam_headers_official as dsh
except ImportError:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    import decode_spam_headers_official as dsh

# Monkey-patch colorizeOutput to preserve markers in JSON format
def patched_colorizeOutput(out, headers):
    if dsh.options['format'] == 'html':
        out = dsh.Logger.htmlColors(out)
        return dsh.formatToHtml(out, headers)
    if dsh.options['format'] == 'text':
        out = dsh.Logger.ansiColors(out)
    # For JSON, do NOT call noColors. Return 'out' with markers for frontend parsing.
    return out

if not LEGACY:
    dsh.colorizeOutput = patched_colorizeOutput

if __name__ == '__main__':
    # This wrapper is now used primarily for JSON output extraction and bug fixes.
    apply_resource_limits()

    output_buffer = BoundedOutput(MAX_OUTPUT_BYTES)
    original_stdout = sys.stdout
    sys.stdout = output_buffer

    try:
        dsh.main(sys.argv)
    except SystemExit:
        pass
    except OutputLimitExceeded:
        sys.stdout = original_stdout
        sys.stderr.write("Wrapper Error: decoder report exceeded the output budget\n")
        sys.exit(1)
    finally:
        sys.stdout = original_stdout

    full_output = output_buffer.getvalue()

    if LEGACY:
        sys.stdout.write(full_output)
        sys.exit(0)

    # Try to find the JSON block in the output
    try:
        start_idx = full_output.find('{')
        end_idx = full_output.rfind('}')
        if start_idx != -1 and end_idx != -1:
            json_str = full_output[start_idx:end_idx+1]
            # Validate it's actual JSON
            json.loads(json_str)
            print(json_str)
        else:
            # If no JSON block found, print everything to stderr so app.py sees the error
            sys.stderr.write(full_output[-4000:])
            sys.exit(1)
    except Exception as e:
        sys.stderr.write(f"Wrapper Error: {str(e)}\nFull Output: {full_output[-4000:]}")
        sys.exit(1)
