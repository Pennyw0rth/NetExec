# nxc Tests
## Running Tests
### Unit Tests
* Install nxc (either in venv or via Poetry)
* Run `pytest` (or `poetry run pytest`)

### End to End Tests
* Install nxc (either in venv or via Poetry): `poetry install --with dev`
* Run `python tests/e2e_tests.py -t $IP -u $USER -p $PASS`, with optional `-k` parameter
  * Poetry: `poetry run python tests/e2e_tests.py -t $IP -u $USER -p $PASS`
* For testing standalone binaries (e.g. windows) run: `python tests/e2e_tests.py --executable dist/nxc.exe -t $IP -u $USER -p $PASS`
* To see full errors (that might show real errors not caught by checking the exit code), run with the `--errors` flag