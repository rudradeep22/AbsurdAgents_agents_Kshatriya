import json
import logging
import os.path
import random
from typing import List, Optional, Tuple
from pwnlib.tubes.remote import remote

import coloredlogs
import pandas as pd
import numpy as np
from tqdm import tqdm
import time

from parse_data import read_all_answers, read_parsed_words, read_past_answers
from play import RIGHT_PLACE, eval_guess, WRONG_PLACE, LETTER_ABSENT
from possibilities_table import (
    array_to_integer,
    load_possibilities_table,
    load_possibilities_table_df,
)

FIRST_GUESS_WORD = "serai"

def prune_table(table: pd.DataFrame, last_guess: str, guess_result: List[int]):
    # modify the table
    columns_to_keep = []
    rval = array_to_integer(guess_result)
    for answer in table.columns:
        if table.loc[last_guess][answer] == rval:
            columns_to_keep.append(answer)
    # print("We're keeping the following columns:")
    # print(columns_to_keep)
    table = table[columns_to_keep]
    table = table[table.index.isin(columns_to_keep)]
    return table

def get_next_guess(table: pd.DataFrame, strategy: str) -> str:
    if strategy == "mean_partition":
        return get_next_guess_mean_partition(table)
    elif strategy == "worst_partition":
        return get_next_guess_worst_partition(table)

def get_next_guess_worst_partition(table: pd.DataFrame) -> str:
    """The table will only contain those words that remain"""
    # compute the max partitions

    def get_worst_partition(row) -> int:
        d = row.value_counts().to_dict()
        return max(d.values())

    # for each remaining guess, compute the worst partition
    part_series = table.apply(get_worst_partition, axis=1)
    # re-index it with words so return value is easier
    part_df = pd.DataFrame(part_series, columns=["worst_partition"], index=table.index)
    # return the word with the smallest worst partition
    i = part_df["worst_partition"].idxmin()
    return i

def solver(words: List[str],conn):
    first_word = "serai"
    strategy = "worst_partition"
    matrix_df_path = "data-parsed\possibilities-table-base-3.npy"
    verbose = True


    if matrix_df_path and matrix_df_path.endswith(".npy"):
        table1 = load_possibilities_table(words)
        table2 = load_possibilities_table(words)
    else:
        table1 = load_possibilities_table_df(matrix_df_path)
        table2 = load_possibilities_table_df(matrix_df_path)

    guesses = [] 
    guess = first_word
    is_solved1 = False
    is_solved2 = False

    while len(guesses) < 8 and (not is_solved2) :
        if guesses == []:
            guess = first_word
        else:
            if not is_solved1:
                if ((table1.shape[0] != 0)):
                    guess = get_next_guess(table1, strategy=strategy)
                elif ((table2.shape[0] != 0)):
                    guess = get_next_guess(table2, strategy=strategy)
                else:
                    guess = "wrong"
            else:
                if ((table2.shape[0] != 0)):
                    guess = get_next_guess(table2, strategy=strategy)
                else:
                    guess = "wrong"
        guesses.append(guess)

        print(conn.recvuntil(b"word: ").decode(),end="")
        print(guess)
        conn.sendline(guess.encode())
        result = conn.recvline().decode()
        if (result[:3] == "You"):
            print(result.strip("\n"))
            return True
        elif (result[:3] == "Sor"):
            print(result.strip("\n"))
            return False
        else:
            print(result.strip("\n"))
        
        print(conn.recvline().decode().strip("\n"))
        guess_result_pre = conn.recvline().decode().strip("\n")
        guess_result1 = guess_result_pre[:5]
        guess_result2 = guess_result_pre[8:]
        print(guess_result_pre)
        result1= []
        result2= []
        for i in guess_result1:
            if ( i == "$"):
                result1.append(RIGHT_PLACE)
            elif( i == "?"):
                result1.append(WRONG_PLACE)
            elif( i == "X"):
                result1.append(LETTER_ABSENT)
        if is_solved1:
            result1 = [2,2,2,2,2]
        for i in guess_result2:
            if ( i == "$"):
                result2.append(RIGHT_PLACE)
            elif( i == "?"):
                result2.append(WRONG_PLACE)
            elif( i == "X"):
                result2.append(LETTER_ABSENT)
        if is_solved2:
            result2 = [2,2,2,2,2]
        print(f"Guess result: {guess_result1} | {guess_result2}")

        if guess == first_word :
            table1 = prune_table(table1, guess, result1)
            print(f"There are now {table1.shape[0]} possibilities of first word")
            table2 = prune_table(table2, guess, result2)
            print(f"There are now {table2.shape[0]} possibilities of second word")
        else :
            if (result1 != [2,2,2,2,2]):
                table1 = prune_table(table1, guess, result1)
                print(f"There are now {table1.shape[0]} possibilities of first word")
                if guess in table2.index:
                    table2 = prune_table(table2, guess, result2)
                    print(f"There are now {table2.shape[0]} possibilities of second word")
            elif (is_solved1) :
                table2 = prune_table(table2, guess, result2)
                print(f"There are now {table2.shape[0]} possibilities of second word")
        if (result1 == [2,2,2,2,2]):
            is_solved1 =True
    print(conn.recvline().decode().strip("\n"))
    return is_solved1 and is_solved2

def solvernoprint(words: List[str],conn,tries,max_tries,min_tries):
    first_word = "serai"
    strategy = "worst_partition"
    matrix_df_path = "data-parsed\possibilities-table-base-3.npy"
    verbose = True


    if matrix_df_path and matrix_df_path.endswith(".npy"):
        table1 = load_possibilities_table(words)
        table2 = load_possibilities_table(words)
    else:
        table1 = load_possibilities_table_df(matrix_df_path)
        table2 = load_possibilities_table_df(matrix_df_path)

    guesses = [] 
    guess = first_word
    is_solved1 = False
    is_solved2 = False

    while len(guesses) < 8 and (not is_solved2) :
        if guesses == []:
            guess = first_word
        else:
            if not is_solved1:
                if ((table1.shape[0] != 0)):
                    guess = get_next_guess(table1, strategy=strategy)
                elif ((table2.shape[0] != 0)):
                    guess = get_next_guess(table2, strategy=strategy)
                else:
                    guess = "wrong"
            else:
                if ((table2.shape[0] != 0)):
                    guess = get_next_guess(table2, strategy=strategy)
                else:
                    guess = "wrong"
        guesses.append(guess)

        conn.recvuntil(b"word: ")
        conn.sendline(guess.encode())
        result = conn.recvline().decode()
        if (result[:3] == "You"):
            tries[0] += len(guesses)
            max_tries[0] = max(len(guesses),max_tries[0])
            min_tries[0] = min(len(guesses),min_tries[0])
            return True
        elif (result[:3] == "Sor"):
            return False
        
        conn.recvline()
        guess_result_pre = conn.recvline().decode().strip("\n")
        guess_result1 = guess_result_pre[:5]
        guess_result2 = guess_result_pre[8:]
        result1= []
        result2= []
        for i in guess_result1:
            if ( i == "$"):
                result1.append(RIGHT_PLACE)
            elif( i == "?"):
                result1.append(WRONG_PLACE)
            elif( i == "X"):
                result1.append(LETTER_ABSENT)
        if is_solved1:
            result1 = [2,2,2,2,2]
        for i in guess_result2:
            if ( i == "$"):
                result2.append(RIGHT_PLACE)
            elif( i == "?"):
                result2.append(WRONG_PLACE)
            elif( i == "X"):
                result2.append(LETTER_ABSENT)
        if is_solved2:
            result2 = [2,2,2,2,2]

        if guess == first_word :
            table1 = prune_table(table1, guess, result1)
            table2 = prune_table(table2, guess, result2)
        else :
            if (result1 != [2,2,2,2,2]):
                table1 = prune_table(table1, guess, result1)
                if guess in table2.index:
                    table2 = prune_table(table2, guess, result2)
            elif (is_solved1) :
                table2 = prune_table(table2, guess, result2)
        if (result1 == [2,2,2,2,2]):
            is_solved1 =True
    return is_solved1 and is_solved2


if __name__ == "__main__":
    server_ip = input("Enter the server Ip :")
    server_port = input("Enter the server port :")
    playing_type = input("Want to play interactive(i) or automatic(a):")
    
    if (playing_type.lower() == "i" ):
        conn = remote(server_ip,server_port)
        print(conn.recvuntil(b">").decode())
        conn.sendline("d".encode())

        words = read_parsed_words()
        solver(words,conn)
        while(input("Do you want to play again(Y/n):").lower()=="y"):
            conn.sendline(b"y")
            solver(words,conn)
    elif (playing_type.lower() == "a" ):
        no_of_plays = int(input("Enter the number of plays:"))
        conn = remote(server_ip,server_port)
        print(conn.recvuntil(b">").decode())
        conn.sendline("d".encode())
        if(no_of_plays == 0):
            exit(0)
        else:
            words = read_parsed_words()
            no_of_wins = 0
            no_of_loss = 0
            streak = 0
            current_streak = 0
            tries = [0]
            max_tries = [0]
            min_tries = [6]
            for i in tqdm(range(no_of_plays), desc="Playing", ascii=True, ncols=100):
                time.sleep(0.1)
                if(solvernoprint(words,conn,tries,max_tries,min_tries)):
                    current_streak +=1
                    no_of_wins +=1
                else : 
                    current_streak = 0
                    no_of_loss +=1
                streak = max(current_streak, streak)
                conn.sendline(b"y")
            print(f"you win {no_of_wins} times and you loss {no_of_loss} times")
            print(f"your highest streak was {streak}")
            print(f"Mean tries it takes to guess are {tries[0]/no_of_wins}")
            print(f"Max tries it takes to guess are {max_tries[0]}")
            print(f"Min tries it takes to guess are {min_tries[0]}")
