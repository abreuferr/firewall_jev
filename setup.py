from setuptools import find_packages, setup

setup(
    name="fwlog",
    version="0.1.0",
    description="Análise de log de firewall OPNsense com Jev (TypeSafe)",
    packages=find_packages(exclude=["tests"]),
    python_requires=">=3.11",
    install_requires=["typesafe-sdk"],
)
