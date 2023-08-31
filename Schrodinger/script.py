from pwnlib.tubes.remote import remote
from tqdm import tqdm
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


def solve( conn):
    sequence = ["2", "3", "4", "4", "3", "2"]
    is_solved = False
    trial = 0
    while not is_solved:
        print(conn.recvuntil(b'position:').decode())
        check = conn.recvline().decode()
        print(check)
        if ("X" in check):
            return True
        guess = sequence[trial]
        print(conn.recvuntil(b'position: ').decode())
        print(guess)
        conn.sendline(guess.encode())
        print(conn.recvline().decode())
        trial+=1
        

        

def solvenoprint(conn, tries, max_tries, min_tries):
    sequence = ["2", "3", "4", "4", "3", "2"]
    is_solved = False
    trial = 0
    while not is_solved:
        conn.recvuntil(b'position:').decode()
        check = conn.recvline().decode()
        check
        if ("X" in check):
            max_tries[0] = max(trial-1, max_tries[0])
            min_tries[0] = min(trial-1, min_tries[0])
            tries[0] += trial-1
            return True
        guess = sequence[trial]
        conn.recvuntil(b'position: ').decode()
        guess
        conn.sendline(guess.encode())
        conn.recvline().decode()
        trial+=1

if __name__ == "__main__":
    args = arg_parser()
    server_ip = input("Enter the server IP : ")
    server_port = input("Enter the port : ")
    playing_type = input("Want to play interactive(i) or automatic(a) : ")
    if playing_type.lower() == 'i' :
        conn = remote(server_ip, server_port)
        print(conn.recvuntil(b">").decode())
        conn.sendline("s".encode())
        solve(conn)
        while(input("Do you want to play again(Y/N): ").lower() == "y"):
            print(conn.recvuntil(b">").decode())
            conn.sendline(b'y')
            solve(conn)
            
    elif playing_type.lower() == 'a' :
        no_of_plays = int(input("Enter the number of plays:"))
        conn = remote(server_ip,server_port)
        print(conn.recvuntil(b">").decode())
        conn.sendline("s".encode())
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
                if solvenoprint(conn,tries,max_tries,min_tries):
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

