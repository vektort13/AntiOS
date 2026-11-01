"""Include the shared Windows resource payload in built Python packages."""
from pathlib import Path
import runpy

from setuptools import setup
from setuptools.command.build_py import build_py


class BuildPy(build_py):
    def run(self):
        super().run()
        helper = Path(__file__).resolve().parent / "scripts/release-payload.py"
        stage = runpy.run_path(str(helper))["stage_runtime"]
        stage(Path(self.build_lib) / "antios/assets/windows")


setup(cmdclass={"build_py": BuildPy})
