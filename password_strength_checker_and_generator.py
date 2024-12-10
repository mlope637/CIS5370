"""
Module Name: Password Strength Checker and Generator (password_strength_checker_and_generator)
Description: This module provides functions to check the strength of your password and generate random passwords.
It also checks the password provided and generated against the HaveIBeenPwnded.com website to check if it was found in a data breach.
Authors: Marco Lopez, Oscar Piloto, Victor Delgado, itsallaboutpython
Date: 2024-12-10
"""

import string
import getpass
import random
import requests  # To access the Pwned Passwords API
import hashlib  # To hash passwords for comparison
import time  # To handle rate-limiting and time-related operations

"""
Original code from GitHub starts in this line
"""

# Constants
RATE_LIMIT = 5  # Maximum number of password-related attempts allowed per minute
attempts = []  # Keeps track of the timestamps for each password-related action

# Function to analyze password strength based on its composition
def check_password_strength(password):
    """
    Analyzes the password's strength by counting various character types
    and estimating its resistance to brute-force attacks.
    """
    # Initialize counters for different character types
    lower_alpha_count = upper_alpha_count = number_count = whitespace_count = special_char_count = 0

    # Count occurrences of each character type in the password
    for char in list(password):
        if char in string.ascii_lowercase:
            lower_alpha_count += 1
        elif char in string.ascii_uppercase:
            upper_alpha_count += 1
        elif char in string.digits:
            number_count += 1
        elif char == ' ':
            whitespace_count += 1
        else:
            special_char_count += 1

    # Calculate the strength score based on the variety of character types
    strength = 0
    remarks = ''

    if lower_alpha_count >= 1:
        strength += 1
    if upper_alpha_count >= 1:
        strength += 1
    if number_count >= 1:
        strength += 1
    if whitespace_count >= 1:
        strength += 1
    if special_char_count >= 1:
        strength += 1

    # Provide feedback based on the strength score
    if strength == 1:
        remarks = "That's a very weak password. Change it as soon as possible."
    elif strength == 2:
        remarks = "That's not a good password. Consider making it tougher."
    elif strength == 3:
        remarks = "Your password is okay, but it can be improved."
    elif strength == 4:
        remarks = "Your password is strong, but you can make it even better."
    elif strength == 5:
        remarks = "Excellent! That's a very strong password."

    """
    New code added
    """
    # Check if the password is found in known breaches and adjust remarks
    if check_password_breach(password):
        remarks += "\nThis password has been found in a data breach. Please use a different password.\n"

    # Estimate the time it would take to crack the password
    crack_years = estimate_cracking_time(password)
    readable_time = convert_readable_years(crack_years)
    remarks += f" It would take approximately {readable_time} to crack this password."
    """
    End of code added
    """
    # Display the analysis
    print("\nYour password has:")
    print(f"{lower_alpha_count} lowercase letters")
    print(f"{upper_alpha_count} uppercase letters")
    print(f"{number_count} digits")
    print(f"{whitespace_count} whitespace characters")
    print(f"{special_char_count} special characters")
    print(f"Password Score: {strength}/5")
    print(f"Remarks: {remarks}")

"""
Original code from GitHub ends in this line
"""
"""
New code for the CIS Project
"""


# Function to generate a random password
def random_password_generator(length=12, uppercase=True, lowercase=True, numbers=True, special_characters=True):
    """
    Generates a random password based on the user's preferences for character types and length.
    """
    # Build a pool of characters based on the selected options
    character_pool = (
        (string.ascii_uppercase if uppercase else "") +
        (string.ascii_lowercase if lowercase else "") +
        (string.digits if numbers else "") +
        (string.punctuation if special_characters else "")
    )

    # Ensure there is at least one character type selected
    if not character_pool:
        raise ValueError("At least one character type must be selected.")

    # Generate a random password and ensure it is not found in known breaches
    while True:
        password = ''.join(random.choice(character_pool) for _ in range(length))
        if not check_password_breach(password):
            break
        print("Generated password found in a data breach. Regenerating...")

    # Estimate the cracking time for the generated password
    crack_years = estimate_cracking_time(password)
    readable_time = convert_readable_years(crack_years)
    print(f"\nGenerated password strength: It would take approximately {readable_time} to crack.")
    return password

# Function to check if a password has been compromised in a breach
def check_password_breach(password):
    """
    Uses the Pwned Passwords API to check if the password has appeared in known data breaches.
    """
    try:
        # Hash the password and get the first 5 characters of the hash
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        first5, tail = sha1_hash[:5], sha1_hash[5:]

        # Query the API and compare hashes
        response = requests.get(f"https://api.pwnedpasswords.com/range/{first5}")
        response.raise_for_status()
        return any(line.split(':')[0] == tail for line in response.text.splitlines())
    except requests.RequestException:
        print("Error: Unable to check password breach due to network issues.")
        return False

# Function to estimate the time required to brute-force a password
def estimate_cracking_time(password):
    """
    Estimates the time it would take to brute-force a password based on its length and complexity.
    """
    # Calculate the size of the character pool
    pool_size = sum([
        len(string.ascii_lowercase) if any(c.islower() for c in password) else 0,
        len(string.ascii_uppercase) if any(c.isupper() for c in password) else 0,
        len(string.digits) if any(c.isdigit() for c in password) else 0,
        len(string.punctuation) if any(c in string.punctuation for c in password) else 0,
    ])

    # Estimate the total number of combinations and cracking time
    total_combinations = pool_size ** len(password)
    attempts_per_second = 1e9  # Assumes a modern attacker can try 1 billion passwords per second
    seconds_per_year = 60 * 60 * 24 * 365
    return total_combinations / (attempts_per_second * seconds_per_year)

# Function to convert cracking time into human-readable format
def convert_readable_years(years):
    """
    Converts a numeric value for years into a readable format like 'million years' or 'billion years'.
    """
    if years < 1_000:
        return f"{years:.2f} years"
    elif years < 1_000_000:
        return f"{years / 1_000:.2f} thousand years"
    elif years < 1_000_000_000:
        return f"{years / 1_000_000:.2f} million years"
    elif years < 1_000_000_000_000:
        return f"{years / 1_000_000_000:.2f} billion years"
    else:
        return f"{years / 1_000_000_000_000:.2f} trillion years"

# Function to enforce a rate limit on user actions
def limited_attempts():
    """
    Limits the number of password-related actions a user can perform within a minute.
    """
    current_time = time.time()
    # Remove attempts older than 60 seconds
    attempts[:] = [t for t in attempts if current_time - t < 60]
    return len(attempts) >= RATE_LIMIT

# Main program loop
while True:
    if limited_attempts():
        print("Too many attempts. Please try again in a minute.")
        time.sleep(60)
        continue

    # Prompt user for action
    choice = input("\nChoose an option: [y] Check password strength, [r] Generate password, [n] Exit: \n").lower()
    
    if 'y' in choice.lower(): # Code taken from GitHub and edited 
        password = getpass.getpass("Enter the password: ")
        attempts.append(time.time()) # New code to check for attempted times
        check_password_strength(password)
    elif 'r' in choice.lower():

        # Ask for password preferences
        while True:
            try:
                length = int(input("Enter desired password length (minimum 8): \n"))
                if length < 8:
                    print("Password length must be at least 8.")
                else:
                    break
            except ValueError:
                print("Invalid input. Please enter a valid number.")

        uppercase = input("Include uppercase letters? (y/n): ").lower() == 'y'
        lowercase = input("Include lowercase letters? (y/n): ").lower() == 'y'
        numbers = input("Include numbers? (y/n): ").lower() == 'y'
        special_characters = input("Include special characters? (y/n): ").lower() == 'y'

        attempts.append(time.time())
        new_password = random_password_generator(length, uppercase, lowercase, numbers, special_characters)
        print(f"\nGenerated password: {new_password}")

    elif 'n' in choice.lower():
        print('A good password contains uppercase, lowercase, numbers, spaces, and special characters.\nThe longer the password, the better security it provides.')
        break
    else:
        print('Invalid input...please try again.')


