from main import HangmanGame
import argparse


def arg_parser():
    parser = argparse.ArgumentParser(description="checker config")
    parser.add_argument("--train_set", type=str, default="words_250000_train.txt",
                        help="path of the train dictionary")
    parser.add_argument("--num_games", type=int, default=1000,
                        help="Number of games for checking")
    args = parser.parse_args()
    return args


args = arg_parser()
game = HangmanGame(args.train_set)
correct = 0
total = args.num_games
for i in range(total):
    result = game.start_game(7)
    print(f"\n\n\n\n Games played {i+1} out of {total}")
    if result:
        correct += 1
print(f'Percentage of correct guesses are: {correct/total * 100}')
