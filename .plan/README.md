# Plan usage

Agents read `.plan/TODO.md` first, work the listed task IDs into commit messages, and when closing an item append `YYYY-MM-DD` in `.plan/DONE.md` before updating the manifest. Archive any finished work by moving it from TODO to DONE, keeping `.plan/ToDo.archive.md` untouched, and rely on `tasks.manifest.json` for the machine-readable view.
