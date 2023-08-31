"""
This file will build the possibilities matrix
"""

from play import LETTER_ABSENT, RIGHT_PLACE, WRONG_PLACE, UNSAFE_eval_guess
from parse_data import read_all_answers, read_parsed_words
import itertools
import os.path
import pickle
from typing import List, Optional, Tuple

import numpy as np
import pandas as pd
from tqdm import tqdm

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
TABLE_PATH = os.path.join(
    BASE_DIR, "data-parsed/possibilities-table-base-3.npy")


def integer_to_arr(rval: int):
    arr = [0] * 5
    for i in range(5, -1, -1):
        # the number at position i
        # should be a value between 0-3
        if rval >= (3 ** i):
            rem = rval % (3 ** i)
            pos_value = int((rval - rem) / (3 ** i))
            arr[i] = pos_value
            rval -= arr[i] * (3 ** i)
    return arr


def guess_response_from_string(guess_response: str) -> int:
    assert len(guess_response) == 5

    def char_to_base_3(s: str) -> int:
        if s == "G":
            return RIGHT_PLACE
        elif s == "Y":
            return WRONG_PLACE
        elif s == "B":
            return LETTER_ABSENT
        else:
            raise Exception(s)

    arr = [char_to_base_3(c) for c in guess_response]
    return array_to_integer(arr)


def guess_response_to_string(rval: int) -> str:
    def base_3_to_char(val: int) -> str:
        if val == RIGHT_PLACE:
            return "G"
        elif val == WRONG_PLACE:
            return "Y"
        elif val == LETTER_ABSENT:
            return "B"
        else:
            raise Exception(val)

    arr = integer_to_arr(rval)
    chars = map(base_3_to_char, arr)
    return "".join(chars)


def array_to_integer(array: List[int]) -> int:
    """
    Convert integer array of 5 into an integer.
    array has 0 for absent, 1 for misplaced and 2 for correct match
    """
    assert isinstance(array, list)
    assert len(array) == 5
    v = 0
    for i, pos_value in enumerate(array):
        assert pos_value < 3 and pos_value >= 0
        v += (3 ** i) * pos_value
    assert v < 255
    return v


def load_possibilities_table(words: List[str]) -> pd.DataFrame:
    """
    The index will represent guesses
    The columns will represent answers
    """
    table = np.load(TABLE_PATH)  # type: np.ndarray
    return pd.DataFrame(table, index=words, columns=words)


def compute_possibilities_table(words: List[str]) -> np.ndarray:
    num_words = len(words)
    print(f"computing {num_words}x{num_words} possibilities matrix...")
    table = np.empty(shape=(num_words, num_words), dtype="uint8")

    def f_eval_guess(guess_i: int, answer_i: int) -> int:
        """Return an integer"""
        guess = words[guess_i]
        answer = words[answer_i]
        rval = UNSAFE_eval_guess(guess=guess, answer=answer)
        # the numbers are guaranteed to be 0, 1, 2
        return array_to_integer(rval)

    word_range_1 = np.arange(num_words)
    word_range_2 = np.arange(num_words)
    combos = itertools.product(word_range_1, word_range_2)
    for guess_i, answer_i in tqdm(combos):
        table[guess_i, answer_i] = f_eval_guess(guess_i, answer_i)

    return table


if __name__ == "__main__":
    words = read_parsed_words()
    print("computing possibilities...")
    table = compute_possibilities_table(words)
    np.save(TABLE_PATH, table)
