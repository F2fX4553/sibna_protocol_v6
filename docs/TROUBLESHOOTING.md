# Sibna Protocol: Troubleshooting Guide

This guide addresses common issues encountered during the build and execution phases of the Sibna Protocol.

---

### 1. Windows: `os error 32` (File Locking)
**Symptoms**: `cargo build` or `pip install` fails with an "Access is Denied" or "File being used by another process" error.

**Solutions**:
- **Antivirus Interference**: Windows Defender or 3rd-party Antivirus often locks newly created `.dll` or `.pdb` files. Add your project directory to the exclusions list.
- **Pending Processes**: Ensure no Python REPL or script using `sibna` is running in the background.
- **WSL Alternative**: If issues persist, development via **WSL2 (Windows Subsystem for Linux)** is highly recommended to avoid NTFS file locking semantics.

### 2. Rust: `cbindgen` Resolution
**Symptoms**: Build fails claiming `cbindgen` is missing or cannot generate headers.

**Solutions**:
- **Manual Install**: Run `cargo install cbindgen`.
- **FFI Feature**: Ensure you are not forcing the `ffi` feature unless you have the C++ header requirements met.

### 3. Python: `ImportError` or `ABI Mismatch`
**Symptoms**: `import sibna` fails with a DLL load error or version mismatch.

**Solutions**:
- **Virtual Environments**: Always use a clean `venv`:
  ```bash
  python -m venv .venv
  source .venv/bin/activate # or .venv\Scripts\activate
  ```
- **Reinstall Bindings**: After rebuilding the Rust core, you must re-run `pip install -e .` in the `bindings/python` directory to sync the shared objects.

### 4. Relay Server: `Address already in use`
**Symptoms**: Server fails to start on port 8000.

**Solutions**:
- Check for ghost processes: `lsof -i :8000` (Unix) or `netstat -ano | findstr :8000` (Windows).
- Change port in `server/main.py` or via command line.
