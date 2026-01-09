import sys
import os
import io
import json

# Import the official script as a module
try:
    import decode_spam_headers_official as dsh
except ImportError:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    import decode_spam_headers_official as dsh

# Monkey-patch Logger.replaceColors to fix the AssertionError
def patched_replaceColors(s, colorizingFunc):
    pos = 0
    while pos < len(s):
        if s[pos:].startswith('__COLOR_'):
            pos += len('__COLOR_')
            pos1 = s[pos:].find('__|')
            if pos1 == -1: break
            c_code = s[pos:pos+pos1]
            try:
                c = int(c_code)
            except ValueError: break
            pos += pos1 + len('__|')
            pos2 = s[pos:].find('|__END_COLOR__')
            if pos2 == -1: break
            txt = s[pos:pos+pos2]
            pos += pos2 + len('|__END_COLOR__')
            patt = f'__COLOR_{c}__|{txt}|__END_COLOR__'
            colored = colorizingFunc(c, txt)
            s = s.replace(patt, colored)
            pos = 0
            continue
        pos += 1
    return s

dsh.Logger.replaceColors = staticmethod(patched_replaceColors)

if __name__ == '__main__':
    # The official script prints headers and info to stdout.
    # We capture everything and then try to find the JSON part.
    
    output_buffer = io.StringIO()
    original_stdout = sys.stdout
    sys.stdout = output_buffer
    
    try:
        dsh.main(sys.argv)
    except SystemExit:
        pass
    finally:
        sys.stdout = original_stdout
    
    full_output = output_buffer.getvalue()
    
    # Check if JSON format was requested
    json_requested = False
    if '-f' in sys.argv:
        try:
            f_index = sys.argv.index('-f')
            if f_index + 1 < len(sys.argv) and sys.argv[f_index + 1] == 'json':
                json_requested = True
        except ValueError:
            pass

    if not json_requested:
        print(full_output)
        sys.exit(0)

    # Try to find the JSON block in the output
    # It usually starts with { and ends with }
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
            sys.stderr.write(full_output)
            sys.exit(1)
    except Exception as e:
        sys.stderr.write(f"Wrapper Error: {str(e)}\nFull Output: {full_output}")
        sys.exit(1)