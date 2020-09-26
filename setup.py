from setuptools import find_packages, setup

setup(
    name="forsee",
    description="Symbolic analysis framework for memory forensics",
    version="0.0.2",
    python_requires=">=3.7",
    packages=find_packages(),
    install_requires=["minidump==0.0.10"],
    extras_require={"dev": ["ipython", "pre-commit", "pytest", "pytest-cov"]},
)
