"""Load `.env` before the tests run.

`cli.main()` does this for the application; pytest does not go through the CLI,
so without this the prefill tests would skip even when TPRM_TOOL_XLSX is set in
`.env`. Keeping the two paths consistent avoids the "it works when I run it,
not when I test it" class of confusion.
"""

from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")
