import string  # For string manipulation functions
import getpass  # For secure password input
import random  # For random number generation
import requests  # To make HTTP requests
import hashlib  # To hash algorithms
import time  # For time-related functions
import os  # To interact with the operating system

RATE_LIMIT = 5  # Set the maximum number of attempts allowed per minute
attempts = []  # Initialize a list to keep track of attempt timestamps

def check_password_strength(password):
    lower_alpha_count = upper_alpha_count = number_count = whitespace_count = special_char_count = 0  # Initialize counters for different character types
    
    for char in list(password):  # Loop through each character in the password
        if char in string.ascii_lowercase:
            lower_alpha_count += 1  # Count lowercase letters
        elif char in string.ascii_uppercase:
            upper_alpha_count += 1  # Count uppercase letters
        elif char in string.digits:
            number_count += 1  # Count digits
        elif char == ' ':
            whitespace_count += 1  # Count whitespaces
        else:
            special_char_count += 1  # Count special characters
    
    strength = 0  # Initialize password strength score
    remarks = ''  # Initialize password remarks
    
    if lower_alpha_count >= 1:
        strength += 1  # Increment strength score if there is at least one lowercase letter
    if upper_alpha_count >= 1:
        strength += 1  # Increment strength score if there is at least one uppercase letter
    if number_count >= 1:
        strength += 1  # Increment strength score if there is at least one digit
    if whitespace_count >= 1:
        strength += 1  # Increment strength score if there is at least one whitespace
    if special_char_count >= 1:
        strength += 1  # Increment strength score if there is at least one special character

    if strength == 1:
        remarks = "That's a very bad password. Change it as soon as possible."  # Set remarks for a very weak password
    elif strength == 2:
        remarks = "That's not a good password. You should consider making a tougher password."  # Set remarks for a weak password
    elif strength == 3:
        remarks = "Your password is okay, but it can be improved a lot."  # Set remarks for an average password
    elif strength == 4:
        remarks = "Your password is hard to guess. But you can make it even more secure."  # Set remarks for a strong password
    elif strength == 5:
        remarks = "Now that's one hell of a strong password! Hackers don't have a chance guessing that password."  # Set remarks for a very strong password

    if check_password_breach(password):  # Check if the password has been compromised in a data breach
        remarks += " This password has been found in a data breach. Choose a different password."  # Append breach warning to remarks

    years_to_crack = estimate_cracking_time(password)  # Estimate the time it would take to crack the password
    readable_time = convert_years_to_readable(years_to_crack)  # Convert the estimated time to a readable format
    remarks += f" It would take approximately {readable_time} to crack this password using a brute-force attack."  # Append cracking time estimate to remarks

    # Print the password analysis
    print("Your password has:-")
    print(f"{lower_alpha_count} lowercase letters")
    print(f"{upper_alpha_count} uppercase letters")
    print(f"{number_count} digits")
    print(f'{whitespace_count} whitespaces')
    print(f"{special_char_count} special characters")
    print(f"Password score: {strength}/5")
    print(f"Remarks: {remarks}")

def generate_random_password(length=12, use_uppercase=True, use_lowercase=True, use_digits=True, use_special_chars=True):
    character_pool = ''  # Initialize the pool of characters based on preferences

    if use_uppercase:
        character_pool += string.ascii_uppercase  # Add uppercase letters to the pool
    if use_lowercase:
        character_pool += string.ascii_lowercase  # Add lowercase letters to the pool
    if use_digits:
        character_pool += string.digits  # Add digits to the pool
    if use_special_chars:
        character_pool += string.punctuation  # Add special characters to the pool

    if not character_pool:
        raise ValueError("At least one character type must be selected.")  # Ensure the character pool is not empty

    while True:  # Loop to ensure a non-breached password is generated
        password = ''.join(random.choice(character_pool) for _ in range(length))  # Generate a random password

        if check_password_breach(password):  # Check if the generated password has been compromised in a data breach
            print("Warning: The generated password has been found in a data breach. Generating a different password...")
        else:
            break  # Break the loop if the password is not found in the breach database

    years_to_crack = estimate_cracking_time(password)  # Estimate the time it would take to crack the password
    readable_time = convert_years_to_readable(years_to_crack)  # Convert the estimated time to a readable format
    print(f"It would take approximately {readable_time} to crack this password using a brute-force attack.")  # Print the cracking time estimate

    return password  # Return the generated password

def check_password_breach(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()  # Hash the password using SHA-1
    first5_char, tail = sha1_password[:5], sha1_password[5:]  # Split the hash into two parts
    response = requests.get(f"https://api.pwnedpasswords.com/range/{first5_char}")  # Query the Have I Been Pwned API
    hashes = (line.split(':') for line in response.text.splitlines())  # Process the API response
    return any(h == tail for h, count in hashes)  # Check if the hash tail is in the response

def estimate_cracking_time(password):
    character_pool_size = 0  # Initialize the size of the character pool
    if any(char.islower() for char in password):
        character_pool_size += len(string.ascii_lowercase)  # Include lowercase letters
    if any(char.isupper() for char in password):
        character_pool_size += len(string.ascii_uppercase)  # Include uppercase letters
    if any(char.isdigit() for char in password):
        character_pool_size += len(string.digits)  # Include digits
    if any(char in string.punctuation for char in password):
        character_pool_size += len(string.punctuation)  # Include special characters
    if ' ' in password:
        character_pool_size += 1  # Include space character

    total_combinations = character_pool_size ** len(password)  # Calculate total possible combinations
    attempts_per_second = 1e9  # Assuming 1 billion attempts per second
    seconds_per_year = 60 * 60 * 24 * 365  # Number of seconds in a year

    years_to_crack = total_combinations / (attempts_per_second * seconds_per_year)  # Estimate years to crack
    return years_to_crack  # Return the estimated years to crack

def convert_years_to_readable(years):
    if years < 1e3:
        return f"{years:.2f} years"
    elif years < 1e6:
        return f"{years / 1e3:.2f} thousand years"
    elif years < 1e9:
        return f"{years / 1e6:.2f} million years"
    elif years < 1e12:
        return f"{years / 1e9:.2f} billion years"
    else:
        return f"{years / 1e12:.2f} trillion years"

def is_rate_limited():
    current_time = time.time()  # Get the current time
    attempts[:] = [attempt for attempt in attempts if current_time - attempt < 60]  # Filter attempts within the last minute
    return len(attempts) >= RATE_LIMIT  # Check if the rate limit is exceeded

print("===== Welcome to Password Strength Checker and Randomizer =====")
while True:
    if is_rate_limited():
        print("Too many attempts. Please try again later.")
        time.sleep(60)
        continue

    choice = input("Do you want to check a password's strength (y), generate a random password (r), or exit (n)? : ")
    if 'y' in choice.lower():
        password = getpass.getpass("Enter the password: ")
        attempts.append(time.time())
        check_password_strength(password)
    elif 'r' in choice.lower():
        while True:
            length_input = input("Enter the desired password length (minimum 8): ")
            if length_input.isdigit():
                length = int(length_input)
                if length < 8:
                    print("Password length should be at least 8.")
                    # Prints a message indicating that the password length should be at least 8 characters.
                else:
                # An else clause that handles the condition when the entered password length is valid.
                   break
                   # Breaks out of the current loop, continuing with the rest of the program execution.
            else:
            # An else clause that handles invalid input cases for the password length.
                   print("Invalid input. Please enter a number.")
                   # Prints a message indicating that the input for the password length was invalid and prompts the user to enter a number.

        use_uppercase = input("Include uppercase letters? (y/n): ").lower() == 'y'
        # Prompts the user to decide whether to include uppercase letters in the password.
        # The input is converted to lowercase and checked if it is 'y'. The result (True or False) is stored in use_uppercase.

        use_lowercase = input("Include lowercase letters? (y/n): ").lower() == 'y'
        # Prompts the user to decide whether to include lowercase letters in the password.
        # The input is converted to lowercase and checked if it is 'y'. The result (True or False) is stored in use_lowercase.

        use_digits = input("Include digits? (y/n): ").lower() == 'y'
        # Prompts the user to decide whether to include digits in the password.
        # The input is converted to lowercase and checked if it is 'y'. The result (True or False) is stored in use_digits.

        use_special_chars = input("Include special characters? (y/n): ").lower() == 'y'
        # Prompts the user to decide whether to include special characters in the password.
        # The input is converted to lowercase and checked if it is 'y'. The result (True or False) is stored in use_special_chars.

        random_password = generate_random_password(length, use_uppercase, use_lowercase, use_digits, use_special_chars)
        # Generates a random password based on the user's preferences for length and character types.
        # Calls the generate_random_password function with the specified parameters and stores the result in random_password.

        print(f"Generated password: {random_password}")
        # Prints the generated password using an f-string to include the value of random_password.

    elif 'n' in choice.lower():
    # An elif clause that checks if the user's choice was to exit the program.
    # The input is converted to lowercase for case-insensitive comparison.

        print('Exiting...')
        # Prints a message indicating that the program is exiting.

        break
        # Breaks out of the while loop, terminating the program.

    else:
    # An else clause that handles any invalid input that does not match the expected options ('y', 'r', or 'n').

        print('Invalid input...please try again.')
        # Prints a message indicating that the input was invalid and prompts the user to try again.

    print()
    # Prints an empty line for better readability of the output.

