# Contributing to Sibna

We welcome contributions from the community! To maintain the security and quality of the Sibna Protocol, please follow these guidelines.

---

### 1. Branching Strategy
- **`main`**: Current stable release. No direct commits allowed.
- **`develop`**: Integration branch for new features. This is the default branch for PRs.
- **`feature/*`**: Individual feature/fix development.

### 2. Development Workflow
1.  **Fork** the repository and create your feature branch.
2.  **Linting**: Ensure your code follows the project's style.
    ```bash
    cargo fmt --all
    cargo clippy --all-targets --all-features -- -D warnings
    ```
3.  **Testing**: All new logic must have unit or integration tests.
    ```bash
    cargo test
    ```
4.  **Documentation**: Update the relevant `.md` files if your change affects the API or protocol.

### 3. Security Disclosure
If you find a security vulnerability, **do not open a public issue.** Please email the security team at `security@sibna.example.com` (replace with real address) for a coordinated disclosure.

### 4. Pull Request Requirements
- Must pass all CI checks.
- Must include a description of the change and why it is needed.
- Should be atomic (one feature/fix per PR).
