Password Strength Checker and Generator.

The Password Strength Checker and Generator is a tool created using Python. It is designed to help users estimate their passwords' strength and generate secure passwords. It also checks the passwords entered or generated against known data breaches using the HaveIBeenPwned API to ensure they have not been compromised.

Password Strength Checker:
-Analyzes the composition of a password.
-Evaluate the passwords' strength based on character variety such as lowercase, uppercase, numbers, special characters, and white spaces.
-Estimates the time required for a bad actor to crack the password using brute force attacks.
-Checks if the password was found in a data breach

Key Features:
1. Password Strength Checker:
-Analyze the password entered for lowercase, uppercase, numbers, special characters, and length.
-Provides a strength score from one to five and personalized feedback.
-Estimates the time required to crack the password using a brute force attack.
-Checks if the password has been found in a data breach.

2. Random Password Generator:
-Allows to customize random passwords with options such as uppercase, lowercase, numbers, and special characters.
-Ensures the password generated was not compromised in data breaches.
-Provides an estimate of the time it would take to crack the password generated.

3. Rate Limiting:
-Prevents extreme attempts by imposing a maximum time of five password checks or generation per minute.

Prerequisites to run the script
-Install Python 3.7 or higher on your system.
-Install requests, hashlib, and getpass libraries.
You can install the libraries required using the following code on the Terminal:
pip install requests
or
pip3 install requests

Installation
1. Clone the repository using the following code:
git clone https://github.com/mlope637/CIS5370/blob/main/password_strength_checker_and_generator.py

2. Navigate to the directory of the project:
cd password_strength_checker_and_generator

3. Run the program:
python3 password_strength_checker_and_generator.py

How to Use the program:
1. Check password strength:
-Select the Check password strength option by typing the letter 'y'.
-Type a password
-Receive feedback on password strength, composition, time to crack, and data breach status.

2. How to Generate Random Password:
-Select the Generate password by typing the letter 'r'.
-Select your preferences on length and character types like uppercase, lowercase, numbers, whitespace, and special characters.
-Receive feedback on the generated password about the time to crack, data breach status, and the password itself.

3. How to Exit the Program:
-Select the Exit option by typing the letter 'n'. 

Authors:
Marco Lopez
Oscar Piloto
Victor Delgado
[itsallaboutpython] (https://github.com/itsallaboutpython)

License:
This project is licensed under the MIT License. Any user can use, modify, and distribute it.

Acknowledgments:
-The Have I Been Pwned API for providing the password breach check.
-The Python community for their robust libraries and resources.
-The [itsallaboutpython](https://github.com/itsallaboutpython) GitHub user is responsible for providing ideas and contributions to part of the code.

Date: December 10, 2024
