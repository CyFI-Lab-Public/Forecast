from setuptools import find_packages, setup

setup(
    name="simprocedures",
    description="SimProcedures for angr",
    version="0.0.1",
    python_requires=">=3.7",
    packages=find_packages(),
    install_requires=["angr"],
    extras_require={"dev": ["ipython", "pre-commit", "pytest", "pytest-cov"]},
)
