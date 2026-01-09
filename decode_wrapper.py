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
            if pos1 == -1: 
                pos += 1
                continue
            c_code = s[pos:pos+pos1]
            try:
                c = int(c_code)
            except ValueError: 
                pos += 1
                continue
            pos += pos1 + len('__|')
            pos2 = s[pos:].find('|__END_COLOR__')
            if pos2 == -1: 
                pos += 1
                continue
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

# Monkey-patch colorizeOutput to preserve markers in JSON format
def patched_colorizeOutput(out, headers):
    if dsh.options['format'] == 'html':
        out = dsh.Logger.htmlColors(out)
        return dsh.formatToHtml(out, headers)
    if dsh.options['format'] == 'text':
        out = dsh.Logger.ansiColors(out)
    # For JSON, do NOT call noColors. Return 'out' with markers for frontend parsing.
    return out

dsh.colorizeOutput = patched_colorizeOutput

if __name__ == '__main__':
    # This wrapper is now used primarily for JSON output extraction and bug fixes.
    
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
            sys.stderr.write(full_output)
            sys.exit(1)
    except Exception as e:
        sys.stderr.write(f"Wrapper Error: {str(e)}\nFull Output: {full_output}")
        sys.exit(1)
