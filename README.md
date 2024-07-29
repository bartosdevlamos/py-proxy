# Proxy Server with Machine Learning

This project provides a proxy server that forwards TCP and UDP traffic from a VPS to a home server. The server incorporates machine learning to filter out malicious traffic. The proxy can run in a learning mode to collect legitimate traffic data and train a model.

## Features

- **TCP and UDP Proxy**: Forwards traffic from VPS to a home server.
- **Machine Learning Integration**: Uses IsolationForest to detect malicious traffic.
- **Learning Mode**: Collects legitimate traffic data and trains a model.

## Prerequisites

- Python 3.x
- Libraries: `asyncio`, `scikit-learn`, `joblib`

Install the required libraries using pip:

```sh
pip install asyncio scikit-learn joblib
