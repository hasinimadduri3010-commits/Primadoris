# Primadoris
# PRIMADORIS
### Intelligence That Uncovers. Vigilance That Protects.

**A layered AI model integrity and continuous trust-monitoring framework.**

Primadoris is a cybersecurity project designed to explore how AI models can be protected against unauthorized modification after deployment. It combines model-file inspection, integrity verification, behavioral monitoring, and security event reporting to help identify potentially compromised AI systems.

The project focuses on a critical challenge in edge AI security: **a model may continue running after deployment even when its underlying files, parameters, or behavior have been altered.**

---

## Table of Contents

- [Overview](#overview)
- [The Problem](#the-problem)
- [Our Approach](#our-approach)
- [Core Features](#core-features)
- [System Architecture](#system-architecture)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Running the Application](#running-the-application)
- [Testing and Demonstration](#testing-and-demonstration)
- [Security Considerations](#security-considerations)
- [Future Scope](#future-scope)
- [Contributing](#contributing)
- [License](#license)

## Overview

AI models are increasingly deployed on edge devices, where they operate outside the controlled environments in which they were developed and tested. These devices may have limited resources and may not always have access to continuous centralized supervision.

Primadoris explores a layered approach to maintaining confidence in deployed AI models by examining their integrity and monitoring their behavior over time.

Rather than relying on a single integrity check, the framework combines complementary mechanisms that can help identify suspicious model artifacts, detect unauthorized changes, and support security decisions.

**Project tagline:** *Intelligence That Uncovers. Vigilance That Protects.*

## The Problem

Traditional model validation generally focuses on whether a model works as expected before deployment. However, the model may be modified after deployment, potentially changing its predictions without immediately causing an obvious failure.

Potential risks include:

- Unauthorized changes to serialized model files.
- Modification of model parameters while the application is running.
- Unexpected changes in model behavior.
- Attempts to use an unverified model in a trusted inference workflow.
- Insufficient visibility into security events and model state changes.

These risks are particularly relevant to edge AI applications, including industrial monitoring, smart energy systems, autonomous systems, and other environments where reliable AI behavior matters.

## Our Approach

Primadoris adopts a layered security approach to examine both the integrity of model artifacts and the behavior of the running system.

### 1. Model Inspection

The scanner examines supported serialized model files for suspicious patterns and potentially unsafe serialization instructions. Its findings help identify artifacts that require further investigation.

### 2. Integrity Verification

Cryptographic hashing can be used to compare model weights against a trusted reference. An attestation-style verification workflow can help determine whether the model presented by an edge device matches the expected integrity state.

### 3. Behavioral Monitoring

Integrity checks alone may not detect every relevant runtime issue. Behavioral monitoring can compare model responses against established baselines to identify unexpected deviations.

### 4. Security Events and Decisions

Detection results and verification outcomes can be presented as structured security events. These events help communicate the type of anomaly, its severity, and the resulting system state.

The layers are designed to complement one another rather than depend on a single detection mechanism.

## Core Features

| Feature | Purpose |
|---|---|
| Model-file scanning | Examine supported serialized artifacts for suspicious patterns. |
| Integrity verification | Compare model integrity information against a trusted reference. |
| Attestation-style checks | Evaluate whether a model satisfies the configured verification workflow. |
| Behavioral deviation analysis | Identify changes in model behavior relative to an established baseline. |
| Controlled tampering simulation | Support testing against representative model modification scenarios. |
| Security event reporting | Organize findings into structured events for investigation. |
| Interactive dashboard | Provide a visual interface for exploring security results and system status. |

*Feature availability depends on the current implementation and configuration of each module.*

## System Architecture

Primadoris is organized around complementary security responsibilities.

### Layer 1 — Model Inspection

Examines serialized model artifacts and reports suspicious findings for further analysis.

### Layer 2 — Integrity and Trust Verification

Uses model integrity information and an attestation-style workflow to evaluate whether a model meets the configured trust requirements.

### Layer 3 — Threat Analysis and Event Reporting

Interprets security findings and verification outcomes, organizes them into meaningful events, and communicates the severity and context of detected deviations.

### Layer 4 — Monitoring and Visualization

Presents system status, findings, and security events through the application interface to support monitoring and demonstration.

### Conceptual Workflow

```text
       AI Model / Model Artifact
                 |
                 v
       +---------------------+
       |  Layer 1            |
       |  Model Inspection   |
       +---------------------+
                 |
                 v
       +---------------------+
       |  Layer 2            |
       |  Integrity & Trust  |
       +---------------------+
                 |
                 v
       +---------------------+
       |  Layer 3            |
       |  Threat Analysis    |
       |  & Event Reporting  |
       +---------------------+
                 |
                 v
       +---------------------+
       |  Layer 4            |
       |  Monitoring & UI    |
       +---------------------+
                 |
                 v
        Security Findings
        and System Status
```

The diagram illustrates the conceptual responsibilities of the layers. The exact execution flow depends on the active application modules.

For implementation details, see [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Technology Stack

Primadoris uses Python and a collection of libraries for model processing, backend services, data handling, and visualization.

- **Python** — core application logic.
- **Streamlit** — interactive dashboard.
- **FastAPI** — API services.
- **Uvicorn** — ASGI server.
- **PyTorch** — model-related operations.
- **NumPy and Pandas** — numerical and data processing.
- **Scikit-learn** — machine learning utilities.
- **Requests and HTTPX** — HTTP communication.
- **Cryptographic hashing and HMAC** — integrity and attestation-style verification logic.

See [`requirements.txt`](requirements.txt) for the repository's declared dependencies.

## Project Structure

The repository contains the following principal files:

```text
Primadoris/
│
├── models/
│   └── Model-related artifacts
│
├── app.py                  # Main Streamlit application
├── app hack.py             # Additional application or experiment
├── api_client.py           # API communication utilities
├── attestation.py          # Attestation and verification logic
├── cloud_server.py         # Server-side verification services
├── config.py               # Configuration
├── make_test_files.py      # Test artifact generation
├── mem1.py                 # Supporting experiment or utility
├── pickle_inspector.py     # Serialized artifact inspection
├── scanner.py              # Model-file scanning
├── split_model.py          # Model-related utilities
├── train_model.py          # Model training or preparation
├── test_scanner.py         # Scanner tests
├── smoke_test_cloud.py     # Cloud-service smoke tests
├── requirements.txt        # Python dependencies
├── ARCHITECTURE.md         # Architecture documentation
├── safe_model.pkl          # Test model artifact
├── malicious_model.pkl     # Test artifact for security analysis
└── README.md               # Project documentation
```

This tree is representative of the repository's current files. Generated files and additional modules may be added as development continues.

## Getting Started

### Prerequisites

- Python 3.10 or a compatible version supported by the installed dependencies.
- Git.
- A terminal or command prompt.
- An internet connection for installing dependencies.

Python version compatibility should be verified if installation fails, particularly for the pinned packages in `requirements.txt`.

### 1. Clone the Repository

```bash
git clone https://github.com/hasinimadduri3010-commits/Primadoris.git
cd Primadoris
```

### 2. Create a Virtual Environment

**Windows**

```bash
python -m venv .venv
.venv\Scripts\activate
```

**Linux or macOS**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If installation fails, check your Python version and the compatibility of the pinned dependency versions.

## Running the Application

### Launch the Dashboard

From the project directory, with the virtual environment activated, run:

```bash
streamlit run app.py
```

Streamlit will display the local URL for the dashboard in the terminal. Open that address in your browser.

### Start the Backend Service

The repository includes `cloud_server.py` for server-side functionality. Its actual startup configuration should be checked in the source file before launching it.

If the application is configured to expose the FastAPI application object as `app`, the following is a typical development command:

```bash
uvicorn cloud_server:app --host 127.0.0.1 --port 8000
```

Run the dashboard and backend together only when the active application configuration requires both services. Check the API client and server settings for the expected connection details.

> **Note:** These are startup instructions for the listed entry points. They do not guarantee that every dashboard feature or backend route is fully configured in every version of the repository.

## Testing and Demonstration

Primadoris includes files for scanner testing, test artifact generation, and cloud-service smoke testing.

To run the scanner test suite:

```bash
python -m pytest test_scanner.py -v
```

If `pytest` is not installed, install it in the active virtual environment:

```bash
python -m pip install pytest
```

For the cloud smoke test, first inspect `smoke_test_cloud.py` to determine whether the backend must be running and which endpoints the test expects. Then execute:

```bash
python smoke_test_cloud.py
```

### Suggested Demonstration Workflow

1. Start the application and any required backend services.
2. Inspect a known test artifact using the scanner functionality.
3. Review the reported findings and verification results.
4. Run only the controlled test scenarios provided for the project.
5. Observe how the application reports changes in integrity or behavior.
6. Review the generated security events and final system status.
7. Reset the demonstration environment before repeating the test.

Use only project-owned or explicitly authorized test artifacts and environments.

## Security Considerations

Primadoris is a research and demonstration project. Its mechanisms should not be treated as a complete production security solution.

- **Scanning is not proof of safety.** A clean scan does not guarantee that an artifact is harmless.
- **Hash verification has limits.** It establishes a comparison against a reference; it does not by itself prove that the reference or verification environment is trustworthy.
- **Simulated attestation is not hardware attestation.** Software-based HMAC verification can demonstrate a trust protocol, but it does not provide the same guarantees as a properly provisioned hardware root of trust.
- **Behavioral monitoring has limits.** A deviation may be caused by legitimate variation, while some malicious changes may not trigger the selected checks.
- **Serialized model files require care.** Only inspect or load trusted artifacts in a controlled environment. Scanning a file does not make unsafe deserialization safe.
- **Production deployment requires additional controls.** These may include protected key storage, authenticated communication, access control, secure updates, robust logging, and independent security testing.

## Future Scope

Potential areas for further development include:

- Hardware-backed attestation using supported trusted execution or security hardware.
- Stronger separation between trusted verification services and edge-device processes.
- Improved behavioral baselines and configurable anomaly thresholds.
- More comprehensive scanner coverage and test cases.
- Clearer event timelines and explainable security alerts.
- Reproducible evaluations against documented test scenarios.
- Performance testing for resource-constrained edge environments.
- Deployment hardening, automated testing, and security documentation.

These are development directions, not claims that the capabilities are already implemented.

## Contributing

Contributions that improve documentation, testing, reliability, and security analysis are welcome.

1. Fork the repository.
2. Create a feature branch.
3. Make a focused change.
4. Run the relevant tests.
5. Submit a pull request describing the change and its validation.

For architecture-sensitive changes, consult [`ARCHITECTURE.md`](ARCHITECTURE.md) before modifying shared interfaces or configuration.

## License

No license information has been confirmed in the repository documentation. Unless a license is added, reuse and redistribution permissions should not be assumed.

## Acknowledgements

Developed as a project exploring AI model integrity, edge AI security, and continuous trust verification.

---

**PRIMADORIS**

*Intelligence That Uncovers. Vigilance That Protects.*
