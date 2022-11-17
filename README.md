# SILENT DATA enclave

The source code in the [enclave](enclave/) directory is executed by SILENT DATA in an Intel SGX enclave.
This code is made public so users of SILENT DATA can be confident that their private data will be handled correctly and securely.

The legitimacy of a SILENT DATA enclave can be ensured by obtaining an Intel attestation service (IAS) report.
This report includes a measurement of the source code that is executed in the enclave, known as the `MRENCLAVE` value.

This measurement can be reproduced from the source code using the instructions below.
In this way, it can be verified that the source code in this repository is exactly what is running in the enclave.

## Tags

Each version of the source code is tagged.
Tags have the form `MRE-*`, where `*` represents the first seven hex characters of the `MRENCLAVE` of the tagged code.

You are currently viewing:

| Tag | `MRENCLAVE` |
|---|---|
| `MRE-d110f61` | `d110f6188ac4c7f511b68060a6ac4a3d8caed1d5abc10dd88ee02bdea14bf252` |

## Reproducible build

To reproducibly build the source code, an installation of Docker is required.
Please run the command below to check Docker is working:
```bash
docker run hello-world
```

The source code can then be built by executing:
```bash
# Point the build script to the enclave/ directory & run the build
./buildsd --source enclave
```

Alternately, a tagged version of the source code can be built by executing:
```bash
# Replace MRE-0000000 with the desired tag
./buildsd --version MRE-0000000
```

This script will:
- Copy the source code to be built into a new directory
- Create a reproducible Docker container with a Nix shell
- Compile the source code in the container
- Sign the enclave with a test private key
- Extract the `MRENCLAVE` of the signed enclave & print the result

The `MRENCLAVE` printed can be compared to the value in the IAS report to confirm that exactly the same code is being executed.
