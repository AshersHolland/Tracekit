# Tracekit test fixtures

`mock_data/` contains small, synthetic artifacts used by the automated tests.
`logs/` contains synthetic log input and a place for captured test-run logs when
tests are executed manually. None of these files represent real case evidence.

The fixture coverage includes:

- CSV exposure totals, sensitive fields, and duplicate rows
- Authentication, network-transfer, and transfer-tool logs
- Identifier pivots across IPs, MACs, hosts, and SSH keys
- Custom byte-field volume analysis
- ZIP/XLSX unpacking
- Filesystem bodyfiles for timeline fusion and timestamp consistency checks
- Mock Sleuth Kit outputs for image initialization and deleted-file recovery tests

Run the tests from the repository root:

```bash
python3 -m unittest discover -s tests -v
```
