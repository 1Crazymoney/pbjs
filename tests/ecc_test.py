"""
Tests the classes in ecc.py
"""

import pytest
from ecc import FieldElement, Point


# TODO: parametrize test
def test_on_curve():
    prime = 223
    a = FieldElement(0, prime)
    b = FieldElement(7, prime)

    valid_points = (
        (192, 105),
        (17, 56),
        (1, 193)
    )
    invalid_points = (
        (200, 119),
        (42, 99)
    )

    for x_raw, y_raw in valid_points:
        x = FieldElement(x_raw, prime)
        y = FieldElement(y_raw, prime)
        Point(x, y, a, b)

    for x_raw, y_raw in invalid_points:
        x = FieldElement(x_raw, prime)
        y = FieldElement(y_raw, prime)
        with pytest.raises(ValueError):
            Point(x, y, a, b)

# TODO: add test to check Point addition