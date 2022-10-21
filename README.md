# Running static analysis
Make sure you are in the root directory of this repo. Then simply run
```mypy .```

# Running tests
Make sure you are in the root directory of this repo. Then simply run
```pytest .```

# Build and Upload package

## Build
```python3 -m build```

## Upload Package to test.pypi
```python3 -m twine upload --repository testpypi dist/it_crypto-0.0.1*```
