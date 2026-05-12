# Reproducibility Guide for ThreatLens

This document provides instructions on how to reproduce the experimental results presented in the SoftwareX paper "ThreatLens: An AI-Assisted DevSecOps Platform for Automated Mobile Application Security Auditing and MASVS v2 Compliance".

## Software Environment

- **OS:** Ubuntu 22.04 LTS (recommended) or any OS with Docker support.
- **Docker:** v24.0.0+
- **Docker Compose:** v2.20.0+
- **Hardware:** 4 vCPUs, 16GB RAM (recommended for concurrent analysis).

## Installation

1. Clone the repository at the specific submission commit:
   ```bash
   git clone https://github.com/hibalahrouf/ThreatLens.git
   cd ThreatLens
   git checkout v1.1.0 # Use the release tag
   ```

2. Configure the environment:
   ```bash
   cp .env.example .env
   # Edit .env to set your LLM backend (Ollama or OpenAI)
   ```

3. Start the platform:
   ```bash
   docker compose up --build -d
   ```

## Running the Benchmark

1. Ensure Ollama is running and Llama-3 is pulled:
   ```bash
   ollama pull llama3
   ```

2. Use the provided benchmark script to scan the evaluation corpus:
   ```bash
   # Download the APKs listed in benchmark/data.csv first
   python benchmark/run_benchmark.py --input benchmark/data.csv --output results/
   ```

## Evaluation Metrics

The results in the paper were calculated using the following formulas:

- **Precision:** $TP / (TP + FP)$
- **Recall:** $TP / (TP + FN)$
- **F1-Score:** $2 \times (Precision \times Recall) / (Precision + Recall)$

Ground truth data for the evaluation corpus is located in `benchmark/ground_truth.json`.


