import hashlib
import itertools
import string

def identify_hash_algorithm(hash_string):
    """Identifies the hashing algorithm based on the length of the hash string."""
    hash_lengths = {
        32: 'md5',
        40: 'sha1',
        56: 'sha224',
        64: 'sha256',
        96: 'sha384',
        128: 'sha512',
    }
    # For SHA3 algorithms which have similar lengths, additional checks can be implemented based on input context if needed.
    return hash_lengths.get(len(hash_string), 'Unknown')

def hash_password(password, algorithm):
    """Hashes the password using the specified algorithm."""
    try:
        hash_function = hashlib.new(algorithm)
        hash_function.update(password.encode())
        return hash_function.hexdigest()
    except ValueError:
        raise ValueError(f"Unsupported or unrecognized hash algorithm: {algorithm}")

def brute_force_cracker(target_hash):
    # Identify the hashing algorithm based on the length
    algorithm = identify_hash_algorithm(target_hash)
    print(f"Detected Hash Algorithm: {algorithm}")

    if algorithm == 'Unknown':
        print("Hash algorithm not recognized based on length. Please verify the target hash.")
        return None

    # Define the character set: lowercase, uppercase, digits, and special characters
    characters = string.ascii_letters + string.digits + string.punctuation

    # Start with password length of 1 and increment if not found
    for password_length in range(1, 6):  # Adjust range as needed for longer passwords
        # Generate all possible combinations of characters for the current length
        for guess in itertools.product(characters, repeat=password_length):
            # Convert the tuple of characters into a string
            guess = ''.join(guess)
            
            # Hash the guessed password using the detected algorithm
            try:
                guess_hash = hash_password(guess, algorithm)
            except ValueError as e:
                print(e)
                return None

            # Print the current guess and hash (can be commented out for faster performance)
            #print(f"Trying: {guess} -> {guess_hash}")

            # Check if the hashed guess matches the target hash
            if guess_hash == target_hash:
                print(f"Password found: {guess}")
                print(f"Used Hash Algorithm: {algorithm}")
                return guess

    print("Password not found within the given range.")
    return None

# Input: Set the target hash you want to crack (hash of a known password for demonstration)
target_hash = input("Enter the target hash to crack: ")
brute_force_cracker(target_hash)
