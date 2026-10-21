import unittest

from first_commit.json_values import is_exact_int, line_number


class JsonValuesTest(unittest.TestCase):
    def test_only_a_plain_int_counts_as_an_int(self) -> None:
        self.assertTrue(is_exact_int(3))
        for value in (True, False, 3.0, "3", None):
            with self.subTest(value=value):
                self.assertFalse(is_exact_int(value))

    def test_a_line_number_is_a_plain_int_from_one_to_the_maximum(self) -> None:
        self.assertEqual(1, line_number(1, 10))
        self.assertEqual(10, line_number(10, 10))
        for value in (0, 11, -1, True, 2.0, "2"):
            with self.subTest(value=value):
                self.assertIsNone(line_number(value, 10))


if __name__ == "__main__":
    unittest.main()
