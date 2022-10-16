from setuptools import setup

setup(
    name="pscanner",
    version="1.0.0",
    packages=["pscanner"],
    include_package_data=True,
    install_requires=["click", "colorama"],
    entry_points={
        "console_scripts": [
            "pscanner=pscanner:port_scanner"
        ]
    }
)
