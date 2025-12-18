use pyo3::prelude::*;
use secure_protocol::{SecureContext, Config, SessionHandle};

/// Python wrapper for Config
#[pyclass]
#[derive(Clone)]
pub struct PyConfig {
    inner: Config,
}

#[pymethods]
impl PyConfig {
    #[new]
    #[pyo3(signature = (
        enable_forward_secrecy=true, 
        enable_post_compromise_security=true,
        max_skipped_messages=1000,
        key_rotation_interval=3600,
        handshake_timeout=60,
        message_buffer_size=1024
    ))]
    fn new(
        enable_forward_secrecy: bool, 
        enable_post_compromise_security: bool,
        max_skipped_messages: usize,
        key_rotation_interval: u64,
        handshake_timeout: u64,
        message_buffer_size: usize,
    ) -> Self {
        let mut cfg = Config::default();
        cfg.enable_forward_secrecy = enable_forward_secrecy;
        cfg.enable_post_compromise_security = enable_post_compromise_security;
        cfg.max_skipped_messages = max_skipped_messages;
        cfg.key_rotation_interval = key_rotation_interval;
        cfg.handshake_timeout = handshake_timeout;
        cfg.message_buffer_size = message_buffer_size;
        PyConfig { inner: cfg }
    }
}

/// Python wrapper for SecureContext
#[pyclass]
pub struct PySecureContext {
    inner: SecureContext,
}

#[pymethods]
impl PySecureContext {
    #[new]
    #[pyo3(signature = (config=None, password=None))]
    fn new(config: Option<PyConfig>, password: Option<&[u8]>) -> PyResult<Self> {
        let cfg = config.map(|c| c.inner).unwrap_or_default();
        let ctx = SecureContext::new(cfg, password)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{}", e)))?;
        Ok(PySecureContext { inner: ctx })
    }

    fn create_session(&self, peer_id: &[u8]) -> PyResult<PySessionHandle> {
        let handle = self.inner.create_session(peer_id).map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{}", e)))?;
        Ok(PySessionHandle { inner: handle }) 
    }

    fn load_identity(&mut self, ed_pub: &[u8], x_pub: &[u8], seed: &[u8]) -> PyResult<()> {
        self.inner.load_identity(ed_pub, x_pub, seed)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{}", e)))
    }

    fn perform_handshake(
        &self,
        peer_id: &[u8],
        initiator: bool,
        peer_ik: Option<&[u8]>,
        peer_spk: Option<&[u8]>,
        peer_opk: Option<&[u8]>,
    ) -> PyResult<Vec<u8>> {
        self.inner.perform_handshake(peer_id, initiator, peer_ik, peer_spk, peer_opk, None)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{}", e)))
    }
    
    fn encrypt_message(&self, session_id: &[u8], plaintext: &[u8]) -> PyResult<Vec<u8>> {
        self.inner.encrypt_message(session_id, plaintext, None)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{}", e)))
    }
    
    fn decrypt_message(&self, session_id: &[u8], ciphertext: &[u8]) -> PyResult<Vec<u8>> {
        self.inner.decrypt_message(session_id, ciphertext, None)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{}", e)))
    }
}

/// Session Handle wrapper
#[pyclass]
pub struct PySessionHandle {
    inner: SessionHandle,
}

#[pymethods]
impl PySessionHandle {
    fn peer_id(&self) -> Vec<u8> {
        self.inner.peer_id().to_vec()
    }
}

/// A Python module implemented in Rust.
#[pymodule]
fn _sibna(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyConfig>()?;
    m.add_class::<PySecureContext>()?;
    m.add_class::<PySessionHandle>()?;
    Ok(())
}
