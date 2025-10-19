# DNS-LLM-T5

**DNS Abuse Detection using T5**

This repository implements the workflow presented at **DNS-OARC 45 (2025)**.  
It provides an end-to-end pipeline for semantic detection of DNS abuse using a T5 model and domain-specific knowledge bases.

## System Overview

1. **DNS Extractor**  
   Extracts query/response fields from raw PCAPs or DNS logs.

2. **Feature Computation**  
   Computes statistical and behavioral features (e.g., query types, TTL entropy, NXDOMAIN ratio, and packet counts.)

3. **LLM Formatter**  
   Converts numeric or categorical features into prompt–response pairs for fine-tuning or inference with T5.

4. **T5 Model Training / Inference**  
   Fine-tunes a T5 to classify DNS traffic into benign or abusive categories.

5. **Knowledge Base Alignment**  
   Integrates structured knowledge from RFCs and DNS abuse taxonomies to enhance interpretability.

## Repository Structure

```
DNS-LLM-T5/
├─ extractor/
│ ├─ dns_extractor.py
│ ├─ compute_features.py
│ └─ llm_formatter.py
├─ model/
│ ├─ train_t5.py
│ ├─ predict_t5.py
│ └─ app_dns_t5.py
├─ knowledge/
│ ├─ dns_attack_taxonomy.json
│ ├─ kb_attacks.json
│ └─ kb_rfcs.json
├─ docs/
│ └─ dns-oarc-presentation-v5.pdf
├─ README.md
├─ requirements.txt
└─ .gitignore
```
