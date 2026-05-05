import gzip
import shutil

with open('stress_test_60k.jsonl', 'rb') as f_in:
    with gzip.open('hydra_payload.jsonl.gz', 'wb') as f_out:
        shutil.copyfileobj(f_in, f_out)
print("Compressed stress_test_60k.jsonl to hydra_payload.jsonl.gz")
