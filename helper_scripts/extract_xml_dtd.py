import os
import re
import subprocess
from datetime import datetime

def run_strings(binary_path, strings_path="strings.exe"):
    """Run strings.exe on the binary and return the output"""
    try:
        # Try default PATH first
        result = subprocess.run([strings_path, binary_path], 
                              capture_output=True, 
                              text=True)
        return result.stdout
    except FileNotFoundError:
        # Try alternate path
        alt_path = os.path.join("c:", "bin", "strings.exe")
        result = subprocess.run([alt_path, binary_path], 
                              capture_output=True, 
                              text=True)
        return result.stdout

def run_sysmon_schema(binary_path):
    """Run Sysmon -s to get the schema and handle output"""
    try:
        # Create a temporary directory for working files
        temp_dir = os.path.join(os.path.dirname(binary_path), "temp_schema")
        os.makedirs(temp_dir, exist_ok=True)
        temp_file = os.path.join(temp_dir, "schema.xml")
        
        print("Attempting with -accepteula -s...")
        
        # Redirect output to a file instead of capturing it
        with open(temp_file, 'wb') as f:
            result = subprocess.run([binary_path, "-accepteula", "-s"],
                                  stdout=f,
                                  stderr=subprocess.PIPE,
                                  creationflags=subprocess.CREATE_NO_WINDOW)
        
        if result.stderr:
            stderr = result.stderr.decode('utf-8', errors='ignore')
            print(f"stderr output: {stderr}")
            
        # Read the generated file if it exists
        if os.path.exists(temp_file):
            with open(temp_file, 'rb') as f:
                content = f.read()
                
            if not content or b'xml' not in content.lower():
                # If first attempt fails, try with just -s
                print("First attempt failed, trying with just -s...")
                with open(temp_file, 'wb') as f:
                    result = subprocess.run([binary_path, "-s"],
                                          stdout=f,
                                          stderr=subprocess.PIPE,
                                          creationflags=subprocess.CREATE_NO_WINDOW)
                
                if result.stderr:
                    print(f"stderr output: {result.stderr.decode('utf-8', errors='ignore')}")
                    
                with open(temp_file, 'rb') as f:
                    content = f.read()
            
            if content:
                # Try to detect if content is UTF-16
                is_utf16 = b'\x00' in content[:4]
                if not is_utf16:
                    # If not UTF-16, remove any stray null bytes
                    content = content.replace(b'\x00', b'')
                decoded = try_decode_content(content)
                
                # Clean up temp directory
                try:
                    os.remove(temp_file)
                    os.rmdir(temp_dir)
                except:
                    pass
                
                # Debug output
                print(f"Raw content length: {len(content)} bytes")
                print(f"Decoded content length: {len(decoded)} characters")
                print("First 200 chars of decoded content:")
                print(decoded[:200])
                
                return decoded
            
        # Clean up temp directory
        try:
            if os.path.exists(temp_file):
                os.remove(temp_file)
            os.rmdir(temp_dir)
        except:
            pass
            
        return None
    except Exception as e:
        print(f"Error running Sysmon -s: {str(e)}")
        return None

def try_decode_content(content):
    """Try different encodings to decode the content"""
    if isinstance(content, str):
        return content
    
    # First try UTF-16 if content looks like it (common for newer Sysmon versions)
    try:
        if b'\x00' in content[:4]:  # Quick check for UTF-16
            return content.decode('utf-16le')
    except UnicodeDecodeError:
        pass
        
    encodings = ['utf-8', 'ascii', 'cp1252']
    
    for encoding in encodings:
        try:
            # Remove BOM if present
            if encoding == 'utf-8' and content.startswith(b'\xef\xbb\xbf'):
                content = content[3:]
                
            # Try to decode
            return content.decode(encoding)
        except UnicodeDecodeError:
            continue
    
    # If all encodings fail, try one last time with UTF-16LE
    try:
        return content.decode('utf-16le', errors='ignore')
    except UnicodeDecodeError:
        return content.decode('utf-8', errors='ignore')

def extract_dtd(content):
    """Extract DTD content from the text"""
    pattern = r'<!DOCTYPE\s+Sysmon\s*\[(.*?)\]>'
    match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
    if match:
        return f"<!DOCTYPE Sysmon [{match.group(1)}]>"
    return None

def extract_xml_from_strings(content):
    """Extract XML content from strings output, stopping at instrumentationManifest"""
    # First find the XML declaration start
    start_match = re.search(r'<\?xml.*?>', content, re.DOTALL)
    if start_match:
        start_pos = start_match.start()
        # Then find the instrumentationManifest end tag
        end_match = re.search(r'</instrumentationManifest>', content[start_pos:], re.DOTALL)
        if end_match:
            end_pos = start_pos + end_match.end()
            return content[start_pos:end_pos]
    return None

def extract_version_from_path(path):
    """Extract version information from folder path"""
    version_pattern = r'.*?v(\d+)_(\d+)'
    match = re.search(version_pattern, path)
    
    if match:
        major, minor = match.groups()
        return (int(major), int(minor)), f"v{major}_{minor}"
    return None, None

def main():
    # Create output directories
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    xml_dir = f"sysmon_schemas_{timestamp}"
    dtd_dir = f"sysmon_dtd_{timestamp}"
    os.makedirs(xml_dir, exist_ok=True)
    os.makedirs(dtd_dir, exist_ok=True)
    
    print(f"Schema files will be saved in: {xml_dir}")
    print(f"DTD files will be saved in: {dtd_dir}")
    
    # Process Sysmon binaries
    file_pattern = r'.*Sysmon.*\.exe$'
    
    for root, _, files in os.walk('.'):
        for file in sorted(files):
            if re.match(file_pattern, file, re.IGNORECASE):
                input_path = os.path.join(root, file)
                
                # Extract version from folder path
                (major, minor), version_str = extract_version_from_path(root)
                if not version_str:
                    print(f"\nSkipping {file} - Unable to determine version from path: {root}")
                    continue
                
                print(f"\nProcessing binary: {file} (Version: {version_str})")
                
                try:
                    # Determine method based on version
                    if major >= 6:  # Version 6.0 and above
                        print("Using Sysmon -s for schema extraction")
                        content = run_sysmon_schema(input_path)
                        # For Sysmon -s output, look for XML content explicitly
                        xml_content = None
                        if content:
                            # Try multiple patterns, handling both UTF-8 and UTF-16 output
                            patterns = [
                                r'(<[\x00]?\?[\x00]?xml.*?</[\x00]?Sysmon[\x00]?>)',
                                r'(<[\x00]?manifest.*?</[\x00]?manifest[\x00]?>)',
                                r'(<[\x00]?Sysmon.*?</[\x00]?Sysmon[\x00]?>)'
                            ]
                            for pattern in patterns:
                                xml_match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
                                if xml_match:
                                    xml_content = xml_match.group(1)
                                    break
                            
                            if not xml_content:
                                print("XML patterns did not match. Content preview:")
                                print(content[:500] if content else "No content")
                    else:  # Version below 6.0
                        print("Using strings.exe for schema extraction")
                        content = run_strings(input_path)
                        xml_content = extract_xml_from_strings(content)
                    
                    # Extract and save DTD
                    if content:
                        dtd_content = extract_dtd(content)
                        if dtd_content:
                            dtd_file = os.path.join(dtd_dir, f"{version_str}_dtd.txt")
                            with open(dtd_file, 'w', encoding='utf-8') as f:
                                f.write(dtd_content)
                            print(f"Successfully extracted DTD to: {dtd_file}")
                            print(f"DTD size: {len(dtd_content)} characters")
                        else:
                            print(f"Could not find DTD content in {file}")
                    
                        # Save XML schema
                        if xml_content:
                            xml_file = os.path.join(xml_dir, f"{version_str}_schema.xml")
                            with open(xml_file, 'w', encoding='utf-8') as f:
                                f.write(xml_content)
                            print(f"Successfully extracted schema to: {xml_file}")
                            print(f"XML size: {len(xml_content)} characters")
                        else:
                            print(f"Could not find XML content in {file}")
                    
                except Exception as e:
                    print(f"Error processing {file}: {str(e)}")
                    import traceback
                    traceback.print_exc()

    print("\nExtraction complete!")

if __name__ == "__main__":
    main()