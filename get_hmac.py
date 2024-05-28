import hashlib, hmac

# Fill in the values of secret_key using the
# values from the Duo protect an application page.
secret_key='' # ex: 'nwR0hBAyosJCZHTvbkvoBuRAe581AtaTxmukwkH6'

def get_hmac(message, skey):
    """
    Return the HMAC signature.
    message: the message for the HMAC signature
    skey: secret key from the Duo integration
    """
    signature = hmac.new(bytes(skey, encoding='utf-8'),
                        bytes(message, encoding='utf-8'),
                        hashlib.sha1)
        
    # Print ASCII message and HMAC signature
    print('')
    print(f'The ASCII message for the HMAC signature:')
    print("______")
    print(f'{message}')
    print("______")
    print(f'The generated HMAC Signature is: {signature.hexdigest()}')
    print('')

    return signature

# Get the information from the user
print("Input the information to generate the HMAC signature.")

# Prompt for secret key if it wasn't already provided
if len(secret_key) == 0:
    secret_key=input("Your Duo protected application secret key: ")

print("Enter/Paste the message for the HMAC signature.")
message = ''
for i in range(5):
    if len(message) > 0:
        message += '\n'
    message += input()

# Generate the HMAC signature.
get_hmac(message, secret_key)