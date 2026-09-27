from pathlib import Path
import xml.etree.ElementTree as ET


def test_guardian_interfaces_declares_ament_cmake_build_type():
    package_xml = (
        Path(__file__).parents[1]
        / "ros2_ws"
        / "src"
        / "guardian_interfaces"
        / "package.xml"
    )
    root = ET.parse(package_xml).getroot()
    build_type = root.find("./export/build_type")

    assert build_type is not None
    assert build_type.text == "ament_cmake"
