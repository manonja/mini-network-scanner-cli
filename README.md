# Mini Network Scanner CLI 🔍

A lightweight command-line tool written in Rust for basic network scanning operations on Linux. Currently supports HTTP port (80) scanning functionality. 

## Quick Start

1. Ensure you have Rust installed on your system
2. Clone this repository
3. Build the project:

```bash
cargo build --release
```

4. Build and run Docker to run the program on Linux (Ubuntu)

```bash
docker build -t my-rust-debug . && docker run -it --name my-rust-debug -v $(pwd):/home/developer/app my-rust-debug
```

5. In Docker:

```bash
$ ~/app cargo build &&  sudo ./target/debug/maja-scan --scan 127.0.0.1:8080 --src 127.0.0.1

```


## Usage

The CLI supports the following commands:

```bash
# Get help and usage information
cli --help
cli -h

# Scan port 80 on a specific IP address
cli --scan <ip_address>
cli -s <ip_address>
```

### Examples

```bash
# Scan localhost
cli --scan 127.0.0.1

# Scan a router (typical address)
cli --scan 192.168.1.1
```

## Technical Details

The scanner performs the following checks:
- Attempts to establish a TCP connection to port 80
- Uses a 1-second timeout for connection attempts
- Returns clear status messages about port accessibility

### Output Format

- Success: "Port 80 is open on {ip}"
- Failure: "Port 80 is closed on {ip}"

## Development

### Linters

1. Format your code:
```bash
cargo fmt
```
Running this command reformats all the Rust code in the current crate. This should only change the code style, not the code semantics.

2. Check for code style issues:
```bash
cargo clippy
```
Running this command checks the Rust code in the current crate for any code style issues.

3. Fix code with rustfix:
```bash
cargo fix
```
The rustfix tool is included with Rust installations and can automatically fix compiler warnings that have a clear way to correct the problem.

### Pre-commit Hooks

The following hooks are configured:
- `cargo-fmt`: Formats your Rust code using rustfmt
- `cargo-clippy`: Runs clippy to catch common mistakes
- `cargo-build`: Ensures your project builds successfully

#### Setting up Pre-commit Hooks

1. Install pre-commit hooks in your repository:
```bash
pre-commit install
```
This sets up a Git hook that runs your defined checks every time you commit.

2. Run Pre-Commit Manually:
```bash
pre-commit run --all-files
```
Use this command to test the hooks before making your first commit.

## Limitations

- Only scans HTTP port (80)
- Basic TCP connection check only
- No service verification
- Some firewalls may block the scan

## Security Note

Please use this tool responsibly and only on networks you own or have explicit permission to scan.

## License

This project is open source and available under the MIT License.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.





