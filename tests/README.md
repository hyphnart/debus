# Manual acceptance test plan

1. Open a PNG, PDF, ZIP and PE executable; check detected magic and headers.
2. Split a 10 MiB file into 3 MiB parts; join it in another directory; compare SHA-256.
3. Modify one byte in a part; join must fail and must not leave a final output.
4. Compare identical files: changedBytes=0, zero ranges.
5. Compare two files with one modified byte: one range of length 1.
6. Compare files with different lengths: extra tail bytes are reported.
7. Open a non-PE file in PE Inspector: must reject.
8. Open a PE32 and PE32+ file: validate section offsets and image base.
9. Cancel split/join/analysis and check output cleanup behavior.
10. Test large files, zero-byte files and paths with Turkish characters.

These are test cases to execute, not claims that automated tests passed.
