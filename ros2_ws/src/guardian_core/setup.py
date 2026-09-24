from pathlib import Path

from setuptools import find_packages, setup

package_name = "guardian_core"
frontend_dir = Path(package_name) / "frontend"
frontend_files = [str(path) for path in frontend_dir.glob("*") if path.is_file()]

setup(
    name=package_name,
    version="0.1.0",
    packages=find_packages(),
    data_files=[
        ("share/ament_index/resource_index/packages", [f"resource/{package_name}"]),
        (f"share/{package_name}", ["package.xml"]),
        (f"share/{package_name}/launch", ["launch/guardian.launch.py"]),
        (f"share/{package_name}/frontend", frontend_files),
    ],
    install_requires=["setuptools"],
    zip_safe=True,
    entry_points={
        "console_scripts": [
            "guardian_node = guardian_core.guardian_node:main",
            "guardian_dashboard = guardian_core.dashboard:main",
            "amr_simulator = guardian_core.amr_simulator:main",
        ],
    },
)

