# Built locally with podman, for the machines where I do not want to
# argue with the system Python: pinned interpreter, format readers
# already installed, and nothing of mine on the host but the bind
# mount.
FROM python:3.12-slim AS build

WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY ckptscan ./ckptscan
COPY scripts ./scripts
RUN pip install --no-cache-dir build \
 && python -m build --wheel --outdir /wheels

FROM python:3.12-slim

# h5py and onnx are in the image so the Keras and ONNX paths are the
# precise ones without thinking about extras. They are the only
# reason this image is not tiny.
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl "ckptscan[all]" \
 && rm -rf /wheels

# Nothing here needs root, and nothing here needs network: the scan is
# static and reads files. Running it with --network none is how I keep
# that claim honest rather than assumed.
RUN useradd --create-home --uid 10001 scanner
USER scanner
WORKDIR /work

ENTRYPOINT ["ckptscan"]
CMD ["--help"]
