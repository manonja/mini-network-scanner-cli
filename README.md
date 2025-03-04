# 🔍 Mini Network Scanner CLI

A lightweight, fast, and efficient command-line network scanning tool written in Rust. This tool allows you to perform TCP SYN scans and retrieve basic system information with minimal overhead. **Note: This tool must run within Docker due to its requirements for raw socket operations on Linux.**

![Rust Version](https://img.shields.io/badge/rust-2021_edition-orange.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Status](https://img.shields.io/badge/status-active-green.svg)
![Platform](https://img.shields.io/badge/platform-docker-blue.svg)

## 📋 Table of Contents
- [🔍 Mini Network Scanner CLI](#-mini-network-scanner-cli)
  - [📋 Table of Contents](#-table-of-contents)
  - [✨ Features](#-features)
  - [🔧 Prerequisites](#-prerequisites)
  - [📥 Installation \& Usage](#-installation--usage)
    - [Example](#example)
  - [📁 Project Structure](#-project-structure)
  - [🛠️ Technologies Used](#️-technologies-used)
  - [🤝 Contributing](#-contributing)
  - [📝 License](#-license)

## ✨ Features

- **TCP SYN Port Scanning**: Port scanning using TCP SYN packets
- **Custom Source IP**: Ability to specify custom source IP addresses for scans
- **HTTP Port Detection**: Scanning for HTTP services (port 80)
- **User-Friendly CLI**: Simple command-line interface
- **Performance**: Written in Rust for performance and safety
- **Containerized**: Runs in Docker for consistent behavior and proper raw socket handling

## 🔧 Prerequisites

- Docker (required)
- Docker Compose (required)
- Git (for cloning the repository)

Note: While the project is written in Rust, you don't need Rust installed locally as the build process happens within Docker.

## 📥 Installation & Usage

This project must run within Docker due to its requirements for raw socket operations on Linux. Here's how to get started:

1. Clone the repository:
```bash
git clone https://github.com/manonja/mini-network-scanner-cli.git
cd mini-network-scanner-cli
```

2. Build the Docker container:
```bash
docker compose build
```

3. Run the scanner:
```bash
# Display help information
docker compose run scanner --help
docker compose run scanner -h

# Perform a TCP SYN scan
docker compose run scanner --scan <ip_address>:<port> --src <source_ip>
docker compose run scanner -s <ip_address>:<port> -r <source_ip>
```

### Example
```bash
docker compose run scanner --scan 192.168.1.1:80 --src 192.168.1.2
```

## 📁 Project Structure

```
.
├── src/
│   ├── main.rs        # Entry point and CLI handling
│   ├── scan.rs        # Core scanning functionality
│   ├── hextools.rs    # Hex manipulation utilities
│   └── net/           # Network-related modules
├── Dockerfile         # Docker configuration
├── compose.yaml       # Docker Compose configuration
└── Cargo.toml        # Project dependencies and metadata
```

## 🛠️ Technologies Used

- **[Rust](https://www.rust-lang.org/)** - Systems programming language
- **[pnet_packet](https://crates.io/crates/pnet_packet)** - Network packet manipulation
- **[socket2](https://crates.io/crates/socket2)** - Socket operations
- **[Docker](https://www.docker.com/)** - Required for running the application

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

Note: Make sure to test your changes within Docker as the project requires Linux for raw socket operations.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

Made with 💜 by Manon Jacquin





