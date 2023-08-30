from pwnlib.tubes.remote import remote
from tqdm import tqdm
from main import HangmanGame
import argparse
import time

def arg_parser():
    parser = argparse.ArgumentParser(description="script config")
    parser.add_argument("--train_set", type=str, default="words_250000_train.txt",
                        help="path of the train dictionary")
    parser.add_argument("--setting", type=str, default="manual",
                        help="manual for playing by yourself \n auto for letting agent play it")
    args = parser.parse_args()
    return args

def solve(game,conn):
    game.guessed_letters = []
    game.current_dictionary = game.full_dictionary
    num_words = len(game.full_dictionary)
    tries_remains = 6
    is_solved = False
    while tries_remains > 0 and not is_solved:
        print(conn.recvuntil(b"word: ").decode(),end="")
        word_seen = conn.recvline().decode().strip("\n")
        print(word_seen)
        word_seen_list = [*(word_seen.lower())]
        if "_" not in word_seen_list:
            print(conn.recvuntil(b"win!\n").decode().strip("\n"))
            return True
            
        guess_letter = game.guess(word_seen_list)
        print(conn.recvuntil(b"word: ").decode(),end="")
        print(guess_letter)
        conn.sendline(guess_letter.encode())
        game.guessed_letters.append(guess_letter)
        result = conn.recvline().decode()
        print(result.strip("\n"))
        if(result[:4] == "Good"):
            continue
        elif (result[5:8] == "not"):
            tries_remains -=1
    print(conn.recvuntil(b"word: ").decode(),end="")
    word_seen = conn.recvline().decode().strip("\n")
    print(word_seen)
    print(conn.recvline().decode().strip("\n"))
    return False
def solvenoprint(game,conn,tries,max_tries,min_tries):
    game.guessed_letters = []
    game.current_dictionary = game.full_dictionary
    num_words = len(game.full_dictionary)
    tries_remains = 6
    is_solved = False
    while tries_remains > 0 and not is_solved:
        conn.recvuntil(b"word: ")
        word_seen = conn.recvline().decode().strip("\n")
        word_seen_list = [*(word_seen.lower())]
        if "_" not in word_seen_list:
            conn.recvuntil(b"win!\n")
            max_tries[0] = max((6-tries_remains),max_tries[0])
            min_tries[0] = min((6-tries_remains),min_tries[0])
            tries[0] += (6-tries_remains)
            return True
            
        guess_letter = game.guess(word_seen_list)
        conn.recvuntil(b"word: ")
        conn.sendline(guess_letter.encode())
        game.guessed_letters.append(guess_letter)
        result = conn.recvline().decode()
        if(result[:4] == "Good"):
            continue
        elif (result[5:8] == "not"):
            tries_remains -=1
    conn.recvuntil(b"word: ")
    word_seen = conn.recvline().decode().strip("\n")
    conn.recvline()
    return False

if __name__ == "__main__":
    args = arg_parser()
    train_set = args.train_set
    game = HangmanGame(train_set)
    server_ip = input("Enter the server Ip :")
    server_port = input("Enter the server port :")
    playing_type = input("Want to play interactive(i) or automatic(a):")

    if (playing_type.lower() == "i" ):
        conn = remote(server_ip,server_port)
        print(conn.recvuntil(b">").decode())
        conn.sendline("h".encode())
        solve(game,conn)
        while(input("Do you want to play again(Y/n):").lower()=="y"):
            print(conn.recvuntil(b">").decode())
            conn.sendline(b"y")
            solve(game,conn)
    elif (playing_type.lower() == "a" ):
        no_of_plays = int(input("Enter the number of plays:"))
        conn = remote(server_ip,server_port)
        print(conn.recvuntil(b">").decode())
        conn.sendline("h".encode())
        if(no_of_plays == 0):
            exit(0)
        else:
            no_of_wins = 0
            no_of_loss = 0
            streak = 0
            current_streak = 0
            tries = [0]
            max_tries = [0]
            min_tries = [6]
            for i in tqdm(range(no_of_plays), desc="Playing", ascii=True, ncols=100):
                time.sleep(0.1)
                if solvenoprint(game, conn,tries,max_tries,min_tries):
                    current_streak +=1
                    no_of_wins += 1
                else:
                    current_streak = 0
                    no_of_loss += 1
                streak = max(current_streak,streak)
                received_data = conn.recvuntil(b">").decode()
                conn.sendline(b"y")
            print(f"you win {no_of_wins} times and you loss {no_of_loss} times")    
            print(f"your highest streak was {streak}")
            print(f"Mean wrong tries it takes to guess are {tries[0]/no_of_wins}")
            print(f"Max wrong tries it takes to guess are {max_tries[0]}")
            print(f"Min wrong tries it takes to guess are {min_tries[0]}")
