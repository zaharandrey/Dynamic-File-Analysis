import os
import sys
import pefile
import lief

def analyze_pe(file_path):
    """Analyze a PE file and list imported libraries and functions."""
    try:
        pe = pefile.PE(file_path)
        print("[+] Detected PE file.")
        print("[+] Imported Libraries and Functions:")
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print(f"\nLibrary: {entry.dll.decode('utf-8')}")
            for imp in entry.imports:
                print(f"  Function: {imp.name.decode('utf-8') if imp.name else 'Ordinal ' + str(imp.ordinal)}")
    except Exception as e:
        print(f"[-] Error analyzing PE file: {e}")

def analyze_elf(file_path):
    """Analyze an ELF file and list imported libraries and functions."""
    try:
        elf = lief.parse(file_path)
        print("[+] Detected ELF file.")
        print("[+] Imported Libraries:")
        for lib in elf.libraries:
            print(f"  {lib}")
        print("[+] Imported Functions:")
        for symbol in elf.imported_symbols:
            print(f"  {symbol.name}")
    except Exception as e:
        print(f"[-] Error analyzing ELF file: {e}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python analyze_file.py <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]

    if not os.path.isfile(file_path):
        print(f"[-] The file {file_path} does not exist.")
        sys.exit(1)

    try:
        with open(file_path, 'rb') as f:
            magic = f.read(4)

        if magic.startswith(b'MZ'):
            analyze_pe(file_path)
        elif magic.startswith(b'\x7fELF'):
            analyze_elf(file_path)
        else:
            print("[-] Unsupported file format.")
    except Exception as e:
        print(f"[-] Error reading file: {e}")

if __name__ == "__main__":
    main()

