# This is a simple binary search game where the player has to guess a number between 1 and 100.

import random

game_number = random.randint(1, 100)
guess = None

print("Welcome to the Binary Search Game!")
print("I have selected a number between 1 and 100.")
print("Try to guess the number using binary search strategy.")

while guess != game_number:
    guess = int(input("Enter your guess: "))
    
    if guess < game_number:
        print("Too low! Try again.")
    elif guess > game_number:
        print("Too high! Try again.")
    else:
        print("Congratulations! You've guessed the correct number.")
