# Robotics Security Mini Corpus

This directory contains a small local corpus for defensive code and data
security experiments.

## Contents

- `data/robomimic/v1.5/lift/ph/low_dim_v15.hdf5`
  - HDF5 demonstration data, about 20 MB.
- `data/lerobot/pusht/`
  - PushT v3.0 data with JSON, Parquet, and MP4 files, about 7.3 MiB.
  - All data/video/metadata files present at the pinned upstream revision
    are included. The upstream `.gitattributes` file is not included.
  - Metadata reports 206 episodes and 25,650 frames. These counts have not
    been independently checked by decoding the Parquet/video files.
- `code/mujoco/`
  - MuJoCo source snapshot and source archive.
- `code/robomimic/`
  - robomimic source snapshot and source archive.
- `code/lerobot/`
  - LeRobot source snapshot and source archive. The archive is authoritative;
    Windows could not create 28 documentation/instruction-file symbolic links.
    All 1,122 regular files were checked against the archive and match.
- `manifest.json`
  - Pinned revisions, provenance, limitations, and SHA-256 hashes for all
    downloaded data files, dataset cards, and source archives.

## Verification and limitations

- Download date: 2026-09-27.
- Data payload: about 27.4 MiB. The entire directory, including extracted
  source and retained source archives, occupies about 352.6 MiB of file content.
- All nine data files and dataset cards match upstream sizes and content
  identifiers at the revisions in `manifest.json`.
- All 3,529 extracted regular source files match their respective archives.
  Source commits were read from the archives' embedded Git commit metadata,
  not inferred from later branch heads.
- Fifty files under `code/lerobot/tests/artifacts/` are Git LFS pointer
  files, not downloaded binary test fixtures. These pointers are present in
  the upstream source archive too. The separately downloaded datasets in
  `data/` are actual payloads, not LFS pointers. The full LeRobot test suite
  cannot be assumed runnable with this source snapshot.
- HDF5, Parquet, and MP4 headers were checked; this is not a full parser or
  playback test. No project was installed, built, or executed.
- `h5py` and `pyarrow` were not installed, so semantic HDF5/Parquet reading
  was not tested. MP4 decoding was not tested.
- These are real-world code/data samples, not a labeled vulnerability
  benchmark. They do not establish vulnerability-detection accuracy.
- The interrupted MuJoCo clone left an incomplete `.git` directory.
  Do not use it as a Git checkout. Scan the extracted source directly,
  excluding `.git` and `*.tar.gz`. The retained archive is the reproducible
  source snapshot.
- Keep the original repository licenses and dataset cards when reusing
  these files. Do not assume all assets or dependencies share one license.

## Suggested first experiment

Start with `code/robomimic/robomimic/` for a small Python static-analysis
run, using `data/robomimic/v1.5/lift/ph/low_dim_v15.hdf5` as a separate
data-loader test input. Use PushT to add Parquet/JSON/video inputs later.
MuJoCo is the optional larger C/C++ target.

The source snapshots are independent static-analysis targets, not a tested
cross-project runtime environment. Installing all three is unnecessary for
an initial scan. Preserve originals and use disposable copies for mutations.

## Safe first checks

Run static checks against the source snapshots and inspect the data parsers
without executing downloaded project code. For dynamic tests, use a
non-root container with no network, no host mounts, and CPU/memory/time limits.
Treat model files, HDF5, Parquet, video, YAML/XML, and downloaded archives as
untrusted input.
