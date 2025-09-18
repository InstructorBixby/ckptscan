"""Keras-shaped fixtures, written from the format rather than with keras.

A `.keras` file is a zip with `config.json` in it, and the only part
this tool reads is that JSON. So the fixtures are the JSON, which means
the test suite needs neither tensorflow nor keras installed -- and the
fixture is readable, which a real saved model is not.

The marshalled payload in the Lambda layer is a base64 string that
decodes to nothing in particular. It exists to be shaped like the real
thing; nothing here produces a runnable code object, because the
detector looks at the layer type and never at the payload.
"""
import base64
import json
import pathlib
import zipfile

INERT_PAYLOAD = base64.b64encode(
    b"ckptscan-inert-marshalled-code-placeholder").decode("ascii")


def dense(name="dense_1", units=8):
    return {"module": "keras.layers", "class_name": "Dense",
            "config": {"name": name, "units": units,
                       "activation": "relu"},
            "registered_name": None}


def lambda_layer(name="lambda_1"):
    return {"module": "keras.layers", "class_name": "Lambda",
            "config": {"name": name,
                       "function": {"class_name": "__lambda__",
                                    "config": {
                                        "code": INERT_PAYLOAD,
                                        "defaults": None,
                                        "closure": None}},
                       "output_shape": None},
            "registered_name": None}


def custom_layer(name="my_layer"):
    return {"module": "mypkg.layers", "class_name": "AttentionThing",
            "config": {"name": name},
            "registered_name": "Custom>AttentionThing"}


def model(layers):
    return {"module": "keras", "class_name": "Sequential",
            "config": {"name": "sequential", "layers": layers},
            "registered_name": None,
            "build_config": {"input_shape": [None, 16]}}


def nested_model(inner_layers):
    """A Lambda buried inside a submodel, which is where they hide."""
    return {"module": "keras", "class_name": "Functional",
            "config": {"name": "outer",
                       "layers": [dense("in"),
                                  model(inner_layers)]},
            "registered_name": None}


def write_keras(path, config):
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("metadata.json",
                   json.dumps({"keras_version": "3.5.0"}))
        z.writestr("config.json", json.dumps(config, indent=1))
        z.writestr("model.weights.h5",
                   b"\x89HDF\r\n\x1a\n" + b"\x00" * 64)
    return path


def write_h5(path, config):
    """Not a real HDF5 file: the magic, then the config as a string.

    Enough to exercise the byte-level fallback, which is the path that
    runs when h5py is not installed. The precise path is tested
    separately and skipped when h5py is missing.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    blob = json.dumps(config).encode("utf-8")
    path.write_bytes(b"\x89HDF\r\n\x1a\n" + b"\x00" * 32
                     + b"model_config" + b"\x00"
                     + blob + b"\x00" * 16)
    return path


def build(out: pathlib.Path):
    made = []
    made.append(write_keras(out / "keras_clean.keras",
                            model([dense("d1"), dense("d2")])))
    made.append(write_keras(out / "keras_lambda.keras",
                            model([dense("d1"), lambda_layer()])))
    made.append(write_keras(out / "keras_nested_lambda.keras",
                            nested_model([lambda_layer("inner")])))
    made.append(write_keras(out / "keras_custom.keras",
                            model([dense("d1"), custom_layer()])))
    made.append(write_h5(out / "keras_clean.h5",
                         model([dense("d1")])))
    made.append(write_h5(out / "keras_lambda.h5",
                         model([lambda_layer()])))
    return made


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="samples/generated")
    args = ap.parse_args()
    for p in build(pathlib.Path(args.out)):
        print(p)
