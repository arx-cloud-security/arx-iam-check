from setuptools import setup, find_packages

setup(
    name="arx-iam-check",
    version="1.1.0",
    packages=find_packages(),
    install_requires=[
        "boto3>=1.20.0",
    ],
    entry_points={
        "console_scripts": [
            "arx-iam-check=arx_iam_check.main:main",
        ],
    },
    python_requires=">=3.9",
    author="ARX Cloud Security",
    description="A read-only IAM security check tool for AWS accounts",
    license="MIT",
)
